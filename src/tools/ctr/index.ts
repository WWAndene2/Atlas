// Public entry point of the 3DS (CTR) format reader: re-exports only.
export { BlzError, blzDecompress, blzDecompressedSize } from "./ctr-blz.js";
export { CtrFormatError, ctrKind, readCtrCode, type CodeSegment, type CtrCode } from "./ctr-container.js";
