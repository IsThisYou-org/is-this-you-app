const path = require('path');
const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');

const config = {
  watchFolders: [path.resolve(__dirname, 'packages')],
  resolver: {
    nodeModulesPaths: [path.resolve(__dirname, 'node_modules')],
    resolveRequest: (context, moduleName, platform) => {
      if (moduleName === '@isthisyou/dnssec-zone') {
        return {
          filePath: path.join(__dirname, 'packages/dnssec-zone/src/index.ts'),
          type: 'sourceFile',
        };
      }
      if (moduleName === '@isthisyou/keystore') {
        return {
          filePath: path.join(__dirname, 'packages/keystore/src/index.ts'),
          type: 'sourceFile',
        };
      }
      if (moduleName === '@isthisyou/keystore/react-native') {
        return {
          filePath: path.join(__dirname, 'packages/keystore/src/react-native.ts'),
          type: 'sourceFile',
        };
      }
      return context.resolveRequest(context, moduleName, platform);
    },
  },
};

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
