/** Minimal declarations — typhonjs-escomplex ships no types (#441). */
declare module 'typhonjs-escomplex' {
  interface ModuleReport {
    maintainability: number;
  }
  const escomplex: {
    analyzeModule(source: string): ModuleReport;
  };
  export default escomplex;
}
