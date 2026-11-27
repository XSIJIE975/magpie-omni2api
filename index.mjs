import { lingmaPlugin } from "./lingma/index.mjs";
import { yunbanPlugin } from "./yunban/index.mjs";

export const lingma = (input, options) => lingmaPlugin(input, options);
export const yunban = (input, options) => yunbanPlugin(input, options);
