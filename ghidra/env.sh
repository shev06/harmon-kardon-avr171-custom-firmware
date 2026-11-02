# Sourced by ghr.sh / ghfresh.sh. Override GHIDRA_HOME / JAVA_HOME in the environment if your install differs.
# Tested with Ghidra 12.2 + OpenJDK 25 installed through Homebrew.
GHIDRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${GHIDRA_HOME:=$(ls -d /opt/homebrew/Cellar/ghidra/*/libexec 2>/dev/null | sort -V | tail -1)}"
: "${JAVA_HOME:=$(ls -d /opt/homebrew/Cellar/openjdk@25/*/libexec/openjdk.jdk/Contents/Home 2>/dev/null | sort -V | tail -1)}"
if [ ! -x "$GHIDRA_HOME/support/analyzeHeadless" ] || [ ! -x "$JAVA_HOME/bin/java" ]; then
  echo "Ghidra/JDK not found (GHIDRA_HOME='$GHIDRA_HOME' JAVA_HOME='$JAVA_HOME'). brew install ghidra openjdk@25, or export both." >&2
  exit 2
fi
export JAVA_HOME PATH="$JAVA_HOME/bin:$PATH"
SCRIPT_PATH="$GHIDRA_DIR/scripts"
