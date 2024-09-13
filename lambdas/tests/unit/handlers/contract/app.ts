import express, { urlencoded, json } from "express";
import limit from "express-rate-limit";
import { Logger } from "@aws-lambda-powertools/logger";
import { Constants, LogLevel } from "./utils/constants";
import { accessTokenRouter } from "./routes/access-token-router";
import { prepareEventMiddleware } from "./middleware/prepare-event-middleware";
const { LOCAL_APP_PORT, TOKEN_ENDPOINT } = Constants;

const logger = new Logger({
    logLevel: LogLevel.DEBUG,
    serviceName: "LocalContractAPI",
});
const app = express();

app.use(urlencoded({ extended: true }));
app.use(json());

const createLimiter = limit({
    windowMs: 10 * 60 * 1000,
    max: 100,
});

app.use(createLimiter);

app.get("/", (_req, res) => {
    res.status(200).json({ msg: "Server is up and running" });
});

app.listen(LOCAL_APP_PORT, () => {
    logger.debug(`Contract testing app listening on port ${LOCAL_APP_PORT}`);
});

app.use(TOKEN_ENDPOINT, prepareEventMiddleware, accessTokenRouter);
