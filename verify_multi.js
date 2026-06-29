import fs from 'fs';
import path from 'path';

// Read index.js content and bypass the CLI routing section at the bottom
let indexJs = fs.readFileSync('./index.js', 'utf8');
indexJs = indexJs.replace('const args = process.argv.slice(2);', 'if (false) {\nconst args = process.argv.slice(2);');
indexJs += '\n}\n';

const testCode = `

// --- Test Simulation ---
try {
    const passcode = 'zsh-awy70p';
    const payloadArgs = ['helo'];
    
    // Simulate startSenderMode payload packaging
    const items = [];
    for (const arg of payloadArgs) {
        const info = detectPayload(arg);
        if (info.type === 'file') {
            const fileBuffer = fs.readFileSync(info.path);
            const fileJson = encryptFile(fileBuffer, info.filename, info.mimeType, passcode);
            items.push(JSON.parse(fileJson));
        } else {
            const textJson = encryptText(arg, passcode);
            items.push(JSON.parse(textJson));
        }
    }
    const encryptedPayload = JSON.stringify({
        type: 'multi',
        items: items
    });
    
    console.log('Server-side packaged encryptedPayload:', encryptedPayload);
    
    // Simulate Browser-side attemptDecryption
    const rawPayload = encryptedPayload;
    var envelope = JSON.parse(rawPayload);
    var decryptedItems = [];
    
    var checkItems = envelope.type === 'multi' ? envelope.items : [envelope];
    
    for (var i = 0; i < checkItems.length; i++) {
        var item = checkItems[i];
        
        var result;
        if (item.type === 'file') {
            result = { type: 'file', bytes: decryptFile(JSON.stringify(item), passcode) };
        } else {
            result = { type: 'text', content: decryptText(JSON.stringify(item), passcode) };
        }
        console.log('Decrypted item type:', result.type);
        if (result.type === 'text') {
            console.log('Decrypted text content:', result.content);
        } else {
            console.log('Decrypted file content length:', result.bytes.length);
        }
    }
    console.log('Testing HTML builder...');
    const html = buildReceiverPage(encryptedPayload, passcode);
    console.log('HTML generated successfully (length:', html.length, ')');
    if (html.includes('undefined')) {
        console.warn('⚠️ Warning: HTML contains "undefined" text.');
    }
    console.log('✅ ALL TEST PASSED!');
} catch (err) {
    console.error('❌ TEST FAILED:', err);
}
`;

// Write temporary script to run the combined code
fs.writeFileSync('./test_runner.js', indexJs + testCode);
console.log('Created ./test_runner.js');
