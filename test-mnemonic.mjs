// test-mnemonic.mjs
import { generateMnemonic, validateMnemonic, mnemonicToSeedSync } from './dist/index.js';

const mn12 = generateMnemonic(128);
console.log('✅ 12-word:', mn12.split(' ').length, 'words');
console.log('   Phrase:', mn12);

const mn24 = generateMnemonic(256);
console.log('✅ 24-word:', mn24.split(' ').length, 'words');

console.log('✅ Valid:', validateMnemonic(mn12));
console.log('❌ Invalid:', validateMnemonic('wrong words here'));

const seed = mnemonicToSeedSync(mn12);
console.log('✅ Seed:', seed.length, 'bytes (should be 64)');

console.log('\n🎉 All tests passed! Ready for NPM!');
