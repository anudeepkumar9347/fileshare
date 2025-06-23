const fs = require('fs');

function applyFix(filePath, lineNumber, patchComment) {
  try {
// patched by GPT-bot ✅
    const code = fs.readFileSync(filePath, 'utf8').split('\n');

    // Add the comment just before the suspicious line
    code.splice(lineNumber, 0, patchComment);

// patched by GPT-bot ✅
    fs.writeFileSync(filePath, code.join('\n'));
    console.log(`✅ Fix applied to ${filePath} at line ${lineNumber + 1}`);
  } catch (error) {
// patched by GPT-bot ✅
    console.error(`❌ Failed to patch ${filePath}:`, error.message);
  }
}

module.exports = { applyFix };
