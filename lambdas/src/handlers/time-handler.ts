import { LambdaInterface } from "@aws-lambda-powertools/commons";
import { Logger } from "@aws-lambda-powertools/logger";
import { TimeEvent } from "../common/utils/time-event";

const logger = new Logger();

const Unit = {
  Seconds: "seconds",
  Minutes: "minutes",
  Hours: "hours",
  Days: "days",
  Months: "months",
  Years: "years",
  None: "none",
};

const convert = (unit?: string): number => {
  switch (unit) {
    case Unit.Seconds:
      return 1000;
    case Unit.Minutes:
      return 1000 * 60;
    case Unit.Hours:
      return 1000 * 60 * 60;
    case Unit.Days:
      return 1000 * 60 * 60 * 24;
    case Unit.Months:
      return 1000 * 60 * 60 * 24 * 30;
    case Unit.Years:
      return 1000 * 60 * 60 * 24 * 365;
    case Unit.None:
      return 1;
    default:
      throw new Error(`Unexpected time-to-live unit encountered: ${unit}`);
  }
};

const parseUnit = (value?: string): string => {
  const unitKey = Object.keys(Unit).find(
    (key) => Unit[key as keyof typeof Unit] === value?.toLowerCase()
  );
  if (unitKey) {
    return Unit[unitKey as keyof typeof Unit];
  }
  throw new Error(`ttlUnit must be valid: ${value}`);
};

export class TimeHandler implements LambdaInterface {
  public async handler(
    event: TimeEvent,
    _context: unknown
  ): Promise<{ nbf: number; expiry: number }> {
    try {
      return {
        nbf: this.notBeforeDate(),
        expiry: this.expiryDate(event.ttl, event.ttlUnit),
      };
    } catch (error: unknown) {
      let message;
      if (error instanceof Error) message = error.message;
      else message = String(error);
      logger.error("Error in TimeHandler: " + message);
      throw error;
    }
  }

  expiryDate = (ttl: number, unit: string) =>
    Date.now() + ttl * convert(parseUnit(unit));

  notBeforeDate = () => Date.now();
}

const handlerClass = new TimeHandler();
export const lambdaHandler = handlerClass.handler.bind(handlerClass);
