import { defineConfig } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';

export default defineConfig({
    plugins: [viteSingleFile()],
    build: {
        outDir: 'dist',
        target: 'es2020',
        minify: 'esbuild',
        // Inline all assets (including Monaco's codicon font) as data URLs
        assetsInlineLimit: 1024 * 1024 * 10,
        rollupOptions: {
            input: 'index.html',
        },
    },
});
