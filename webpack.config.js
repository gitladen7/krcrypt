const path = require("path");

module.exports = env => {
    return {
        entry: "./src/index.ts",
        mode: 'production',
        module: {
            rules: [
                {
                    test: /\.tsx?$/,
                    use: "ts-loader",
                    exclude: /node_modules/
                }
            ]
        },
        resolve: {
            extensions: [".tsx", ".ts", ".js", ".json"]
        },
        output: {
            filename: "krcrypt.js",
            path: path.resolve(__dirname, "dist")
        },
        target: "node",
    };
}