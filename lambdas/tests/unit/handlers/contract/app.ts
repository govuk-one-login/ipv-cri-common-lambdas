import express, { urlencoded, json } from "express";
import { Logger } from "@aws-lambda-powertools/logger";
import { Constants, LogLevel } from "./utils/constants";
import { accessTokenRouter } from "./routes/access-token-router";
import { prepareEventMiddleware } from "./middleware/prepare-event-middleware";
const { LOCAL_APP_PORT } = Constants;

const logger = new Logger({
    logLevel: LogLevel.DEBUG,
    serviceName: "LocalContractAPI",
});
const app = express();

app.use(urlencoded({ extended: true }));
app.use(json());

app.get("/", (req, res) => {
    res.status(200).json({ msg: "Server is up and running" });
});

app.listen(LOCAL_APP_PORT, () => {
    logger.debug(`Contract testing app listening on port ${LOCAL_APP_PORT}`);
});

app.use("/access-token", prepareEventMiddleware, accessTokenRouter);
