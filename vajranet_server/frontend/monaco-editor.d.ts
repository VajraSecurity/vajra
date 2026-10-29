// `monaco-editor`'s package.json only declares types for its full barrel
// (`monaco-editor/esm/vs/editor/editor.main`), which pulls in every bundled
// language. We import the slim subpaths below instead to keep the bundle
// small — TS just needs to know they resolve.
declare module 'monaco-editor/esm/vs/editor/editor.api' {
  import * as monaco from 'monaco-editor';
  export import editor = monaco.editor;
  export import Environment = monaco.Environment;
}

declare module 'monaco-editor/esm/vs/basic-languages/sql/sql.contribution';