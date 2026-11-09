module.exports = {
  dependency: {
    platforms: {
      android: {
        sourceDir: './android',
        packageImportPath: 'import com.isthisyou.keystore.KeystorePackage;',
        packageInstance: 'new KeystorePackage()',
      },
    },
  },
};
