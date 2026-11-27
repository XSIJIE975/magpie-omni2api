// 插件入口。宿主把本文件的每个函数导出都当作一个插件调用，任何一个抛错都会
// 导致整包没有 hooks，所以这里只导出 lingma 与 yunban。
export { lingma, yunban } from "./index.mjs";
