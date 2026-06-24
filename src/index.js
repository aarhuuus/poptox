const express = require('express');
const crypto = require('crypto');
const { JSDOM } = require('jsdom');
const { Innertube, UniversalCache } = require('youtubei.js');
const { BG } = require('bgutils-js');

const app = express();
app.use(express.json());

// CONFIGURATION
const PORT = process.env.PORT || 3000;
const TOKEN_CACHE_TTL = parseInt(process.env.TOKEN_TTL || '21600', 10); // 6 hours
const MAX_CACHE_SIZE = parseInt(process.env.MAX_CACHE_SIZE || '1000', 10);
const API_KEY = process.env.API_KEY || null;
const REQUEST_KEY = process.env.REQUEST_KEY || 'O43z0dpjhgX20SCx4KAo';
const NODE_ENV = process.env.NODE_ENV || 'production';

const tokenCache = new Map();
const integrityTokenCache = new Map();

const SUPPORTED_CLIENTS = ['web', 'mweb', 'web_music', 'web_creator', 'android', 'ios', 'tv'];
const SUPPORTED_CONTEXTS = ['gvs', 'player', 'subs'];

// HELPERS
function cleanupCache() {
    const now = Date.now();
    let cleaned = 0;
    for (const [key, entry] of tokenCache.entries()) {
        if (entry.expiresAt < now) {
            tokenCache.delete(key);
            cleaned++;
        }
    }
    if (cleaned > 0) {
        console.log(`[Cache] Cleaned up ${cleaned} expired entries. Size: ${tokenCache.size}`);
    }
}
setInterval(cleanupCache, 5 * 60 * 1000);

function getCacheKey(videoId, client, context, visitorData, dataSyncId) {
    const data = `${videoId}:${client}:${context}:${visitorData || ''}:${dataSyncId || ''}`;
    return crypto.createHash('sha256').update(data).digest('hex');
}

function base64ToU8(base64) {
    const base64Clean = base64.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64Clean.padEnd(base64Clean.length + (4 - base64Clean.length % 4) % 4, '=');
    return new Uint8Array(Buffer.from(padded, 'base64'));
}

function u8ToBase64(u8, websafe = false) {
    const base64 = Buffer.from(u8).toString('base64');
    if (websafe) {
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    return base64;
}

function generateVisitorData() {
    const randomBytes = crypto.randomBytes(16);
    return randomBytes.toString('base64').replace(/[+/=]/g, '');
}

// MIDDLEWARE
function authMiddleware(req, res, next) {
    if (!API_KEY) return next();
    const providedKey = req.headers['x-api-key'] || req.query.api_key;
    if (providedKey !== API_KEY) {
        return res.status(401).json({ success: false, error: 'Unauthorized. Invalid or missing API key.' });
    }
    next();
}

function logRequest(req, res, next) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${req.method} ${req.path} - IP: ${req.ip}`);
    next();
}

app.use(logRequest);

// BGUTILS TOKEN GENERATION
async function fetchInnerTubeChallenge(visitorData) {
    console.log('[BgUtils] Creating Innertube session...');

    const innertube = await Innertube.create({
        retrieve_player: false,
        cache: new UniversalCache(false)
    });

    const actualVisitorData = visitorData || innertube.session.context.client.visitorData;
    if (!actualVisitorData) {
        throw new Error('Could not obtain visitor data from Innertube session');
    }

    console.log(`[BgUtils] Visitor data: ${actualVisitorData.substring(0, 20)}...`);

    const challengeResponse = await innertube.getAttestationChallenge('ENGAGEMENT_TYPE_UNBOUND');

    if (!challengeResponse.bg_challenge) {
        throw new Error('Could not get BotGuard challenge from InnerTube');
    }

    const interpreterUrl = challengeResponse.bg_challenge.interpreter_url
        .private_do_not_access_or_else_trusted_resource_url_wrapped_value;

    const bgScriptResponse = await fetch(`https:${interpreterUrl}`);
    const interpreterJavascript = await bgScriptResponse.text();

    return {
        innertube,
        visitorData: actualVisitorData,
        interpreterJavascript,
        interpreterHash: challengeResponse.bg_challenge.interpreter_hash,
        program: challengeResponse.bg_challenge.program,
        globalName: challengeResponse.bg_challenge.global_name
    };
}

function loadBotGuardVM(interpreterJavascript, globalName) {
    console.log('[BgUtils] Loading BotGuard VM into JSDOM...');

    const dom = new JSDOM('<!DOCTYPE html><html><head></head><body></body></html>', {
        runScripts: 'dangerously',
        url: 'https://www.youtube.com',
        referrer: 'https://www.youtube.com/',
        pretendToBeVisual: true,
        resources: 'usable'
    });

    const window = dom.window;
    const document = window.document;

    Object.assign(globalThis, {
        window, document,
        location: window.location,
        navigator: window.navigator,
        localStorage: window.localStorage,
        sessionStorage: window.sessionStorage,
        XMLHttpRequest: window.XMLHttpRequest,
        WebSocket: window.WebSocket,
        fetch: window.fetch,
        Request: window.Request,
        Response: window.Response,
        Headers: window.Headers,
        URL: window.URL,
        URLSearchParams: window.URLSearchParams,
        TextEncoder: window.TextEncoder,
        TextDecoder: window.TextDecoder,
        crypto: window.crypto,
        performance: window.performance,
        console: window.console
    });

    if (interpreterJavascript) {
        const vmFunc = new Function(interpreterJavascript);
        vmFunc();
    } else {
        throw new Error('Could not load VM: interpreterJavascript is null');
    }

    const vm = globalThis[globalName];
    if (!vm) {
        throw new Error(`VM not found in global scope under name: ${globalName}`);
    }

    console.log(`[BgUtils] VM loaded: ${globalName}`);
    return { vm, window, document };
}

async function executeBotGuardSnapshot(vm, program, contentBinding) {
    console.log('[BgUtils] Executing BotGuard program...');

    if (!vm.a) {
        throw new Error('[BotGuardClient] vm.a is not available');
    }

    const vmFunctions = {};

    const vmFunctionsCallback = (
        asyncSnapshotFunction,
        shutdownFunction,
        passEventFunction,
        checkCameraFunction
    ) => {
        Object.assign(vmFunctions, {
            asyncSnapshotFunction,
            shutdownFunction,
            passEventFunction,
            checkCameraFunction
        });
    };

    try {
        const syncSnapshotFunction = await vm.a(
            program,
            vmFunctionsCallback,
            true,
            undefined,
            () => { },
            [[], []]
        )[0];

        const webPoSignalOutput = [];

        const botguardResponse = await new Promise((resolve, reject) => {
            if (!vmFunctions.asyncSnapshotFunction) {
                return reject(new Error('[BotGuardClient]: Async snapshot function not found'));
            }

            vmFunctions.asyncSnapshotFunction((response) => {
                resolve(response);
            }, [
                contentBinding || undefined,
                undefined,
                webPoSignalOutput,
                undefined
            ]);
        });

        console.log('[BgUtils] Snapshot executed successfully');
        return { botguardResponse, webPoSignalOutput, vmFunctions };

    } catch (error) {
        throw new Error(`[BotGuardClient] Failed to execute program: ${error.message}`);
    }
}

async function getPoIntegrityToken(requestKey, botguardResponse) {
    console.log('[BgUtils] Requesting integrity token from WAA...');

    const payload = [requestKey, botguardResponse];

    const response = await fetch('https://jnn-pa.googleapis.com/$rpc/google.internal.waa.v1.Waa/GenerateIT', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json+protobuf',
            'x-goog-api-key': 'AIzaSyDyT5W0Jh49F30Pqqtyfdf7pDLFKLJoAnw',
            'x-user-agent': 'grpc-web-javascript/0.1',
        },
        body: JSON.stringify(payload)
    });

    if (!response.ok) {
        throw new Error(`WAA GenerateIT failed: ${response.status} ${response.statusText}`);
    }

    const integrityTokenJson = await response.json();
    const [integrityToken, estimatedTtlSecs, mintRefreshThreshold, websafeFallbackToken] = integrityTokenJson;

    console.log(`[BgUtils] Integrity token received. TTL: ${estimatedTtlSecs}s`);

    return {
        integrityToken,
        estimatedTtlSecs,
        mintRefreshThreshold,
        websafeFallbackToken
    };
}

async function mintPoToken(webPoSignalOutput, integrityToken, contentBinding) {
    console.log('[BgUtils] Minting PO token...');

    const getMinter = webPoSignalOutput[0];
    if (!getMinter) {
        throw new Error('PMD:Undefined - Minter function not found');
    }

    const mintCallback = await getMinter(base64ToU8(integrityToken || ''));
    if (!(mintCallback instanceof Function)) {
        throw new Error('APF:Failed - Mint callback is not a function');
    }

    const result = await mintCallback(new TextEncoder().encode(contentBinding));
    if (!result) {
        throw new Error('YNJ:Undefined - Mint result is empty');
    }
    if (!(result instanceof Uint8Array)) {
        throw new Error('ODM:Invalid - Mint result is not a Uint8Array');
    }

    const poToken = u8ToBase64(result, true);
    console.log(`[BgUtils] PO token minted: ${poToken.substring(0, 30)}...`);
    return poToken;
}

async function generatePOToken(videoId, client, context, visitorData, dataSyncId) {
    const startTime = Date.now();
    console.log(`\n[Generate] video=${videoId}, client=${client}, context=${context}`);

    try {
        let actualVisitorData = visitorData;
        if (!actualVisitorData) {
            actualVisitorData = generateVisitorData();
            console.log(`[Generate] Generated visitor data: ${actualVisitorData.substring(0, 20)}...`);
        }

        let contentBinding;
        let identifier;

        if (context === 'player') {
            contentBinding = videoId;
            identifier = videoId;
        } else {
            contentBinding = actualVisitorData;
            identifier = actualVisitorData;
        }

        console.log(`[Generate] Content binding: ${contentBinding.substring(0, 20)}... (${context})`);

        const challengeData = await fetchInnerTubeChallenge(actualVisitorData);
        const { vm } = loadBotGuardVM(challengeData.interpreterJavascript, challengeData.globalName);
        const { botguardResponse, webPoSignalOutput } = await executeBotGuardSnapshot(vm, challengeData.program, contentBinding);
        const integrityTokenData = await getPoIntegrityToken(REQUEST_KEY, botguardResponse);
        const poToken = await mintPoToken(webPoSignalOutput, integrityTokenData.integrityToken, identifier);

        const generationTime = Date.now() - startTime;
        console.log(`[Generate] Completed in ${generationTime}ms\n`);

        return {
            po_token: poToken,
            visitor_data: actualVisitorData,
            data_sync_id: dataSyncId || null,
            integrity_token_data: {
                estimated_ttl_secs: integrityTokenData.estimatedTtlSecs,
                mint_refresh_threshold: integrityTokenData.mintRefreshThreshold
            }
        };

    } catch (error) {
        console.error(`[Generate] FAILED: ${error.message}`);
        throw error;
    }
}

// API ENDPOINTS
app.get('/health', (req, res) => {
    const uptime = process.uptime();
    const memoryUsage = process.memoryUsage();
    res.json({
        status: 'healthy',
        uptime: `${Math.floor(uptime / 60)}m ${Math.floor(uptime % 60)}s`,
        cache: {
            tokenCacheSize: tokenCache.size,
            integrityTokenCacheSize: integrityTokenCache.size,
            maxSize: MAX_CACHE_SIZE,
            ttl: TOKEN_CACHE_TTL
        },
        memory: {
            used: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`,
            total: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`
        },
        version: '2.0.0-render',
        engine: 'BgUtils (LuanRT)',
        supportedClients: SUPPORTED_CLIENTS,
        supportedContexts: SUPPORTED_CONTEXTS
    });
});

app.get('/ping', (req, res) => {
    res.json({ status: 'ok', version: '2.0.0-render' });
});

app.post('/api/v1/token', authMiddleware, async (req, res) => {
    try {
        const {
            video_id,
            client = 'web',
            context = 'gvs',
            visitor_data = null,
            data_sync_id = null,
            force_refresh = false
        } = req.body;

        if (!video_id) {
            return res.status(400).json({ success: false, error: 'Missing required parameter: video_id' });
        }
        if (!/^[a-zA-Z0-9_-]{11}$/.test(video_id)) {
            return res.status(400).json({ success: false, error: 'Invalid video_id format' });
        }
        if (!SUPPORTED_CLIENTS.includes(client)) {
            return res.status(400).json({ success: false, error: 'Unsupported client', supported: SUPPORTED_CLIENTS });
        }
        if (!SUPPORTED_CONTEXTS.includes(context)) {
            return res.status(400).json({ success: false, error: 'Unsupported context', supported: SUPPORTED_CONTEXTS });
        }

        const cacheKey = getCacheKey(video_id, client, context, visitor_data, data_sync_id);

        if (!force_refresh && tokenCache.has(cacheKey)) {
            const cached = tokenCache.get(cacheKey);
            if (cached.expiresAt > Date.now()) {
                console.log(`[Cache] Hit for ${video_id} (${client}/${context})`);
                return res.json({
                    success: true,
                    cached: true,
                    data: {
                        video_id, client, context,
                        po_token: cached.token,
                        visitor_data: cached.visitorData,
                        data_sync_id: cached.dataSyncId,
                        created_at: new Date(cached.createdAt).toISOString(),
                        expires_at: new Date(cached.expiresAt).toISOString(),
                        ttl_remaining: Math.floor((cached.expiresAt - Date.now()) / 1000)
                    }
                });
            }
            tokenCache.delete(cacheKey);
        }

        console.log(`[Generate] Generating PO token for ${video_id} (${client}/${context})`);
        const startTime = Date.now();
        const tokenData = await generatePOToken(video_id, client, context, visitor_data, data_sync_id);
        const generationTime = Date.now() - startTime;

        if (tokenCache.size >= MAX_CACHE_SIZE) {
            const firstKey = tokenCache.keys().next().value;
            tokenCache.delete(firstKey);
        }

        tokenCache.set(cacheKey, {
            token: tokenData.po_token,
            visitorData: tokenData.visitor_data,
            dataSyncId: tokenData.data_sync_id,
            client, context,
            createdAt: Date.now(),
            expiresAt: Date.now() + (TOKEN_CACHE_TTL * 1000)
        });

        res.json({
            success: true,
            cached: false,
            generation_time_ms: generationTime,
            data: {
                video_id, client, context,
                po_token: tokenData.po_token,
                visitor_data: tokenData.visitor_data,
                data_sync_id: tokenData.data_sync_id,
                integrity_token_data: tokenData.integrity_token_data,
                created_at: new Date().toISOString(),
                expires_at: new Date(Date.now() + (TOKEN_CACHE_TTL * 1000)).toISOString(),
                ttl: TOKEN_CACHE_TTL
            }
        });

    } catch (error) {
        console.error('[Error] Token generation failed:', error.message);
        res.status(500).json({
            success: false,
            error: 'Token generation failed',
            message: error.message,
            stack: NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

app.post('/api/v1/token/batch', authMiddleware, async (req, res) => {
    try {
        const { requests } = req.body;
        if (!Array.isArray(requests) || requests.length === 0) {
            return res.status(400).json({ success: false, error: 'requests must be a non-empty array' });
        }
        if (requests.length > 50) {
            return res.status(400).json({ success: false, error: 'Maximum batch size is 50' });
        }

        const results = [];
        const errors = [];

        for (let i = 0; i < requests.length; i++) {
            const reqItem = requests[i];
            try {
                const { video_id, client = 'web', context = 'gvs', visitor_data = null, data_sync_id = null } = reqItem;
                if (!video_id || !/^[a-zA-Z0-9_-]{11}$/.test(video_id)) {
                    throw new Error('Invalid or missing video_id');
                }

                const cacheKey = getCacheKey(video_id, client, context, visitor_data, data_sync_id);
                let tokenData;

                if (tokenCache.has(cacheKey)) {
                    const cached = tokenCache.get(cacheKey);
                    if (cached.expiresAt > Date.now()) {
                        tokenData = { po_token: cached.token, visitor_data: cached.visitorData, data_sync_id: cached.dataSyncId, cached: true };
                    }
                }

                if (!tokenData) {
                    tokenData = await generatePOToken(video_id, client, context, visitor_data, data_sync_id);
                    tokenData.cached = false;
                    if (tokenCache.size >= MAX_CACHE_SIZE) {
                        const firstKey = tokenCache.keys().next().value;
                        tokenCache.delete(firstKey);
                    }
                    tokenCache.set(cacheKey, {
                        token: tokenData.po_token,
                        visitorData: tokenData.visitor_data,
                        dataSyncId: tokenData.data_sync_id,
                        client, context,
                        createdAt: Date.now(),
                        expiresAt: Date.now() + (TOKEN_CACHE_TTL * 1000)
                    });
                }

                results.push({ index: i, success: true, video_id, client, context, ...tokenData });
            } catch (err) {
                errors.push({ index: i, success: false, video_id: reqItem.video_id, error: err.message });
            }
        }

        res.json({
            success: true,
            summary: { total: requests.length, successful: results.length, failed: errors.length },
            results,
            errors: errors.length > 0 ? errors : undefined
        });

    } catch (error) {
        res.status(500).json({ success: false, error: 'Batch processing failed', message: error.message });
    }
});

// yt-dlp plugin primary endpoint
app.post('/get_pot', authMiddleware, async (req, res) => {
    try {
        const { video_id, client = 'web', context = 'gvs', visitor_data = null, data_sync_id = null } = req.body;
        const targetVideoId = video_id || 'default';
        const cacheKey = getCacheKey(targetVideoId, client, context, visitor_data, data_sync_id);

        if (tokenCache.has(cacheKey)) {
            const cached = tokenCache.get(cacheKey);
            if (cached.expiresAt > Date.now()) {
                return res.json({
                    po_token: cached.token,
                    visitor_data: cached.visitorData,
                    data_sync_id: cached.dataSyncId,
                    client, context,
                    cached: true
                });
            }
            tokenCache.delete(cacheKey);
        }

        const tokenData = await generatePOToken(targetVideoId, client, context, visitor_data, data_sync_id);

        if (tokenCache.size >= MAX_CACHE_SIZE) {
            const firstKey = tokenCache.keys().next().value;
            tokenCache.delete(firstKey);
        }
        tokenCache.set(cacheKey, {
            token: tokenData.po_token,
            visitorData: tokenData.visitor_data,
            dataSyncId: tokenData.data_sync_id,
            client, context,
            createdAt: Date.now(),
            expiresAt: Date.now() + (TOKEN_CACHE_TTL * 1000)
        });

        res.json({
            po_token: tokenData.po_token,
            visitor_data: tokenData.visitor_data,
            data_sync_id: tokenData.data_sync_id,
            client, context,
            cached: false
        });

    } catch (error) {
        console.error('[Error] /get_pot failed:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Legacy GET endpoint
app.get('/api/v1/yt-dlp/token', authMiddleware, async (req, res) => {
    try {
        const { client = 'web', video_id = null, visitor_data = null, data_sync_id = null, context = 'gvs' } = req.query;
        if (!SUPPORTED_CLIENTS.includes(client)) {
            return res.status(400).json({ success: false, error: 'Unsupported client', supported: SUPPORTED_CLIENTS });
        }

        const targetVideoId = video_id || 'default';
        const cacheKey = getCacheKey(targetVideoId, client, context, visitor_data, data_sync_id);

        if (tokenCache.has(cacheKey)) {
            const cached = tokenCache.get(cacheKey);
            if (cached.expiresAt > Date.now()) {
                return res.json({
                    po_token: cached.token,
                    visitor_data: cached.visitorData,
                    data_sync_id: cached.dataSyncId,
                    client, context,
                    cached: true
                });
            }
            tokenCache.delete(cacheKey);
        }

        const tokenData = await generatePOToken(targetVideoId, client, context, visitor_data, data_sync_id);

        if (tokenCache.size >= MAX_CACHE_SIZE) {
            const firstKey = tokenCache.keys().next().value;
            tokenCache.delete(firstKey);
        }
        tokenCache.set(cacheKey, {
            token: tokenData.po_token,
            visitorData: tokenData.visitor_data,
            dataSyncId: tokenData.data_sync_id,
            client, context,
            createdAt: Date.now(),
            expiresAt: Date.now() + (TOKEN_CACHE_TTL * 1000)
        });

        res.json({
            po_token: tokenData.po_token,
            visitor_data: tokenData.visitor_data,
            data_sync_id: tokenData.data_sync_id,
            client, context,
            cached: false
        });

    } catch (error) {
        console.error('[Error] yt-dlp endpoint failed:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Cache management
app.get('/api/v1/cache/stats', authMiddleware, (req, res) => {
    const entries = Array.from(tokenCache.entries()).map(([key, value]) => ({
        key: key.substring(0, 16) + '...',
        client: value.client,
        context: value.context,
        expires_in: Math.floor((value.expiresAt - Date.now()) / 1000)
    }));
    res.json({ size: tokenCache.size, maxSize: MAX_CACHE_SIZE, ttl: TOKEN_CACHE_TTL, entries: entries.slice(0, 100) });
});

app.delete('/api/v1/cache', authMiddleware, (req, res) => {
    const size = tokenCache.size;
    tokenCache.clear();
    res.json({ success: true, message: `Cache cleared. Removed ${size} entries.` });
});

app.post('/invalidate_caches', authMiddleware, (req, res) => {
    const size = tokenCache.size;
    tokenCache.clear();
    res.json({ success: true, message: `All caches invalidated. Removed ${size} entries.` });
});

app.post('/invalidate_it', authMiddleware, (req, res) => {
    const size = integrityTokenCache.size;
    integrityTokenCache.clear();
    res.json({ success: true, message: `Integrity token cache invalidated. Removed ${size} entries.` });
});

app.get('/minter_cache', authMiddleware, (req, res) => {
    res.json({ integrityTokenCacheSize: integrityTokenCache.size, tokenCacheSize: tokenCache.size });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        available_endpoints: [
            'GET  /health',
            'GET  /ping',
            'POST /api/v1/token',
            'POST /api/v1/token/batch',
            'GET  /api/v1/yt-dlp/token',
            'POST /get_pot',
            'GET  /api/v1/cache/stats',
            'DELETE /api/v1/cache',
            'POST /invalidate_caches',
            'POST /invalidate_it',
            'GET  /minter_cache'
        ]
    });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('[Error] Unhandled error:', err);
    res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: NODE_ENV === 'development' ? err.message : 'Something went wrong'
    });
});

// START SERVER

app.listen(PORT, () => {
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log(`║  Server running on port: ${PORT.toString().padEnd(37)} ║`);
    console.log(`║  Cache TTL: ${TOKEN_CACHE_TTL.toString().padEnd(43)} ║`);
    console.log(`║  Max Cache Size: ${MAX_CACHE_SIZE.toString().padEnd(39)} ║`);
    console.log(`║  API Key Protected: ${(API_KEY ? 'Yes' : 'No').padEnd(35)} ║`);
    console.log('╚════════════════════════════════════════════════════════════╝');
    console.log('');
    console.log('Powered by BgUtils (https://github.com/LuanRT/BgUtils)');
    console.log('');
});

module.exports = app;
