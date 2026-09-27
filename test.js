// Import the NAPI-RS generated JavaScript wrapper
const nativeAddon = require('./index.js');

console.log("Scanning system for hidden processes...");

try {
  // Call the Rust function we exposed with #[napi]
  // Note: NAPI-RS converts snake_case (get_hidden_processes) to camelCase automatically
  const hiddenProcesses = nativeAddon.getHiddenProcesses();
const sus = nativeAddon.getSuspiciousProcesses();
console.log(sus)
console.log(`Scan complete. Found ${hiddenProcesses.length} process(es) hidden from capture.\n`);

  if (hiddenProcesses.length === 0) {
    console.log("No hidden processes detected.");
  } else {
    hiddenProcesses.forEach((proc) => {
      console.log(`========================================`);
      console.log(`PID:             ${proc.pid}`);
      console.log(`Name:            ${proc.name}`);
      console.log(`Escaped/Debug:   ${proc.nameDebug}`);
      console.log(`Codepoints:      ${proc.codepoints}`);
      console.log(`Full Path:       ${proc.fullPath || '<Access Denied or Exited>'}`);
      if (proc.pathCodepoints) {
        console.log(`Path Codepoints: ${proc.pathCodepoints}`);
      }
    });
    console.log(`========================================`);
  }
} catch (error) {
  console.error("An error occurred during scanning:", error);
}
