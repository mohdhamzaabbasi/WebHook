const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser'); // Ensures raw body parsing
const Joi = require('joi');
const app = express();
app.use(bodyParser.text({ type: '*/*' }));
app.use(express.json()); // Ensures JSON parsing

// Function to normalize payload
function normalizePayload(payload) {
    return {
        api_json: {
            timing: payload?.api_json?.actions?.find(action => action._class === 'jenkins.metrics.impl.TimeInQueueAction') || {},
            artifacts: payload?.api_json?.artifacts || [],
            building: payload?.api_json?.building || false,
            description: payload?.api_json?.description || null,
            displayName: payload?.api_json?.displayName || '',
            duration: payload?.api_json?.duration || 0,
            estimatedDuration: payload?.api_json?.estimatedDuration || 0,
            executor: payload?.api_json?.executor || null,
            fullDisplayName: payload?.api_json?.fullDisplayName || '',
            id: payload?.api_json?.id || '',
            keepLog: payload?.api_json?.keepLog || false,
            number: payload?.api_json?.number || 0,
            queueId: payload?.api_json?.queueId || 0,
            result: payload?.api_json?.result || 'UNKNOWN',
            timestamp: payload?.api_json?.timestamp || 0,
            url: payload?.api_json?.url || '',
            changeSets: payload?.api_json?.changeSets || [],
            culprits: payload?.api_json?.culprits || [],
            inProgress: payload?.api_json?.inProgress || false,
            nextBuild: {
                number: payload?.api_json?.nextBuild?.number || null,
                url: payload?.api_json?.nextBuild?.url || null
            },
            previousBuild: {
                number: payload?.api_json?.previousBuild?.number || null,
                url: payload?.api_json?.previousBuild?.url || null
            }
        },
        wfapi_describe: {
            _links: { self: payload?.wfapi_describe?._links?.self || {} },
            id: payload?.wfapi_describe?.id || '',
            name: payload?.wfapi_describe?.name || '',
            status: payload?.wfapi_describe?.status || 'UNKNOWN',
            startTimeMillis: payload?.wfapi_describe?.startTimeMillis || 0,
            endTimeMillis: payload?.wfapi_describe?.endTimeMillis || 0,
            durationMillis: payload?.wfapi_describe?.durationMillis || 0,
            queueDurationMillis: payload?.wfapi_describe?.queueDurationMillis || 0,
            pauseDurationMillis: payload?.wfapi_describe?.pauseDurationMillis || 0,
            stages: payload?.wfapi_describe?.stages || []
        }
    };
}


// Define schema for validating `api_json`
const apiJsonSchema = Joi.object({
    _class: Joi.string().required(),
    actions: Joi.array().items(
        Joi.object({
            _class: Joi.string().optional(),
            causes: Joi.array().optional(),
            blockedDurationMillis: Joi.number().optional(),
            blockedTimeMillis: Joi.number().optional(),
            buildableDurationMillis: Joi.number().optional(),
            buildableTimeMillis: Joi.number().optional(),
            buildingDurationMillis: Joi.number().optional(),
            executingTimeMillis: Joi.number().optional(),
            executorUtilization: Joi.number().optional(),
            subTaskCount: Joi.number().optional(),
            waitingDurationMillis: Joi.number().optional(),
            waitingTimeMillis: Joi.number().optional(),
            buildsByBranchName: Joi.object().optional(),
            lastBuiltRevision: Joi.object().optional(),
            remoteUrls: Joi.array().items(Joi.string().uri()).optional(),
            scmName: Joi.string().allow('').optional()
        })
    ).required(),
    artifacts: Joi.array().required(),
    building: Joi.boolean().required(),
    description: Joi.string().allow(null),
    displayName: Joi.string().required(),
    duration: Joi.number().required(),
    estimatedDuration: Joi.number().required(),
    executor: Joi.string().allow(null),
    fullDisplayName: Joi.string().required(),
    id: Joi.string().required(),
    keepLog: Joi.boolean().required(),
    number: Joi.number().required(),
    queueId: Joi.number().required(),
    result: Joi.string().valid('SUCCESS', 'FAILURE', 'ABORTED', 'UNSTABLE').required(),
    timestamp: Joi.number().required(),
    url: Joi.string().uri().required(),
    changeSets: Joi.array().required(),
    culprits: Joi.array().required(),
    inProgress: Joi.boolean().required(),
    nextBuild: Joi.object({
        number: Joi.number().required(),
        url: Joi.string().uri().required()
    }).required(),
    previousBuild: Joi.object({
        number: Joi.number().required(),
        url: Joi.string().uri().required()
    }).required()
});

// Define schema for validating `wfapi_describe`
const wfapiDescribeSchema = Joi.object({
    _links: Joi.object({
        self: Joi.object({
            href: Joi.string().pattern(/^\/[\w-]+(\/[\w-]+)*$/).required()
        }).required()
    }).required(),
    id: Joi.string().required(),
    name: Joi.string().required(),
    status: Joi.string().valid('SUCCESS', 'FAILED', 'ABORTED', 'IN_PROGRESS','NOT_EXECUTED').required(),
    startTimeMillis: Joi.number().required(),
    endTimeMillis: Joi.number().required(),
    durationMillis: Joi.number().required(),
    queueDurationMillis: Joi.number().required(),
    pauseDurationMillis: Joi.number().required(),
    stages: Joi.array().items(
        Joi.object({
            _links: Joi.object().required(),
            id: Joi.string().required(),
            name: Joi.string().required(),
            execNode: Joi.string().allow(''),
            status: Joi.string().valid('SUCCESS', 'FAILED', 'ABORTED', 'IN_PROGRESS','NOT_EXECUTED').required(),
            startTimeMillis: Joi.number().required(),
            durationMillis: Joi.number().required(),
            pauseDurationMillis: Joi.number().required(),
            error: Joi.string().optional()
        })
    ).required()
});



// Function to parse JSON
function parseJson(payload) {
    try {
        return JSON.parse(payload.trim());
    } catch (error) {
        console.error("Invalid JSON format.");
        return null;
    }
}

// Function to verify authorization
function verifyAuthorization(req) {
    const encryptedTimestamp = req.header("X-Encrypted-Timestamp");
    if (!encryptedTimestamp) {
        return { success: false, message: "Missing encrypted timestamp" };
    }

    const decryptedTimestamp = Number(encryptedTimestamp.split("").reverse().join(""));
    if (isNaN(decryptedTimestamp)) {
        return { success: false, message: "Invalid encrypted timestamp" };
    }

    const currentTime = Date.now();
    if (currentTime < decryptedTimestamp + 600000) {
        console.log("Authorization verified!");
        return { success: true };
    } else {
        console.error("Authorization denied.");
        return { success: false, message: "Authorization denied" };
    }
}

// Function to check data integrity
function verifyChecksum(req, receivedPayload) {
    const receivedChecksum = req.header('X-Payload-Checksum');
    const computedChecksum = crypto.createHash('sha256').update(receivedPayload, 'utf8').digest('hex');

    if (receivedChecksum === computedChecksum) {
        console.log("Data integrity verified!");
        return { success: true };
    } else {
        console.error("Checksum mismatch! Possible data tampering.");
        return { success: false, message: "Checksum mismatch. Possible data corruption." };
    }
}


app.post('/webhook', (req, res) => {
    console.log("AAYA");
    const receivedPayload = req.body;
    
    // Step 1: Parse JSON
    const parsedPayload = parseJson(receivedPayload);
    if (!parsedPayload) {
        return res.status(400).send("Invalid JSON format.");
    }


    //Normalize Data
    const normalizedData = normalizePayload(receivedPayload);
    console.log("Normalized Data:", JSON.stringify(normalizedData, null, 2));

    // Step 2: Verify Authorization
    const authResult = verifyAuthorization(req);
    if (!authResult.success) {
        return res.status(400).send(authResult.message);
    }

    // Step 3: Check Data Integrity
    const checksumResult = verifyChecksum(req, receivedPayload);
    if (!checksumResult.success) {
        return res.status(400).send(checksumResult.message);
    }
    // Validate `api_json`
    const { error: apiJsonError } = apiJsonSchema.validate(parsedPayload.api_json);
    if (apiJsonError) {
        console.error("api_json validation failed:", apiJsonError.details[0].message);
        return res.status(400).send(`api_json validation error: ${apiJsonError.details[0].message}`);
    }
    // Validate `wfapi_describe`
    const { error: wfapiDescribeError } = wfapiDescribeSchema.validate(parsedPayload.wfapi_describe);
    if (wfapiDescribeError) {
        console.error("wfapi_describe validation failed:", wfapiDescribeError.details[0].message);
        return res.status(400).send(`wfapi_describe validation error: ${wfapiDescribeError.details[0].message}`);
    }
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
