#!/bin/sh
# End-to-end parity check: lint a real Ruby tree with oxidecop AND real
# rubocop (restricted to the cops oxidecop implements), then diff the
# normalized offense lists. This is the acceptance test for the project's
# actual selling point — same offenses on real code, not just on spec
# fixtures. Exit 0 = byte-identical offense sets.
#
#   tools/parity.sh <ruby-source-dir>
#   tools/parity.sh "$(dirname "$(gem which rubocop)")/rubocop"   # rubocop's own source
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TARGET=${1:?usage: parity.sh <ruby-source-dir>}
[ -d "$TARGET" ] || { echo "not a directory: $TARGET" >&2; exit 2; }
BIN="$ROOT/target/release/oxidecop"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Keep in sync with oracle/leaderboard.rb COPS (the implemented set).
COPS="Style/NilComparison,Style/NumericPredicate,Style/ZeroLengthPredicate,Style/RedundantReturn,Style/NumericLiterals,Style/StringLiterals,Style/Documentation,Style/FrozenStringLiteralComment,Style/SymbolProc,Naming/MethodName,Lint/NestedMethodDefinition,Layout/LineLength,Layout/TrailingWhitespace,Style/EvenOdd,Lint/RandOne,Style/ArrayJoin,Lint/BooleanSymbol,Lint/BigDecimalNew,Style/Dir,Style/StringChars,Style/NestedFileDirname,Lint/UriRegexp,Lint/UnifiedInteger,Lint/EmptyEnsure,Lint/EmptyExpression,Lint/UriEscapeUnescape,Style/UnpackFirst,Style/RandomWithOffset,Lint/Debugger,Style/NegatedIf,Lint/EmptyFile,Layout/TrailingEmptyLines,Layout/InitialIndentation,Style/NegatedWhile,Style/CharacterLiteral,Style/UnlessElse,Lint/EmptyInterpolation,Lint/EnsureReturn,Style/EndBlock,Style/BeginBlock,Naming/ConstantName,Naming/ClassAndModuleCamelCase,Naming/BinaryOperatorParameterName,Lint/DuplicateRequire,Style/StderrPuts,Style/WhileUntilDo,Style/MultilineIfThen,Style/Not,Style/ColonMethodCall,Lint/EmptyClass,Lint/DeprecatedClassMethods,Layout/EmptyLineAfterMagicComment,Layout/EmptyLines,Style/EmptyLiteral,Style/Semicolon,Style/GlobalVars,Layout/SpaceAfterComma,Layout/SpaceBeforeSemicolon,Style/DefWithParentheses,Layout/SpaceBeforeComma,Layout/SpaceBeforeComment,Lint/FloatOutOfRange,Style/SymbolLiteral,Lint/RescueException,Style/WhenThen,Lint/DuplicateHashKey,Security/MarshalLoad,Layout/SpaceAfterMethodName,Layout/SpaceAfterSemicolon,Layout/SpaceAfterNot,Lint/UnifiedInteger,Lint/FlipFlop,Style/Proc,Lint/DuplicateCaseCondition,Lint/DuplicateElsifCondition,Style/ColonMethodDefinition,Layout/LeadingEmptyLines,Style/Strip,Lint/TopLevelReturnWithArgument,Security/Eval,Style/VariableInterpolation,Lint/EachWithObjectArgument,Style/TrailingBodyOnModule,Lint/RegexpAsCondition,Lint/DuplicateRescueException,Style/TrailingBodyOnClass,Lint/SafeNavigationWithEmpty,Style/RedundantCapitalW,Lint/HashCompareByIdentity,Lint/NextWithoutAccumulator,Layout/SpaceAfterColon,Lint/MultipleComparison,Style/EmptyLambdaParameter,Layout/SpaceInsideArrayPercentLiteral,Style/IfUnlessModifierOfIfUnless,Style/EmptyBlockParameter,Lint/IdentityComparison,Layout/SpaceInsideRangeLiteral,Style/DoubleCopDisableDirective,Style/ClassCheck,Naming/BlockParameterName,Style/ClassMethods,Style/TrailingBodyOnMethodDefinition,Lint/UselessElseWithoutRescue,Lint/ReturnInVoidContext,Style/MultilineBlockChain,Style/OptionalArguments,Style/RedundantFileExtensionInRequire,Lint/TrailingCommaInAttributeDeclaration,Layout/ConditionPosition,Naming/HeredocDelimiterNaming,Style/MultilineWhenThen,Naming/MethodParameterName,Style/MultilineIfModifier,Layout/EmptyLinesAroundBeginBody,Layout/EmptyLinesAroundBlockBody,Style/ClassVars,Lint/NestedPercentLiteral,Lint/PercentSymbolArray,Style/MinMax,Style/TrailingMethodEndStatement,Style/OptionalBooleanParameter,Layout/SpaceInsideStringInterpolation,Layout/EmptyLinesAroundMethodBody,Style/NestedTernaryOperator,Layout/AssignmentIndentation,Lint/CircularArgumentReference,Lint/BinaryOperatorWithIdenticalOperands,Lint/InterpolationCheck,Lint/FloatComparison,Layout/SpaceInsidePercentLiteralDelimiters,Lint/EmptyWhen,Lint/InheritException,Lint/ConstantDefinitionInBlock,Lint/ElseLayout,Layout/EmptyLinesAroundModuleBody,Lint/DisjunctiveAssignmentInConstructor,Lint/IneffectiveAccessModifier,Layout/LeadingCommentSpace,Lint/DeprecatedOpenSSLConstant,Lint/AssignmentInCondition,Layout/EmptyLinesAroundClassBody,Lint/AmbiguousRegexpLiteral,Layout/BlockEndNewline,Metrics/CyclomaticComplexity,Metrics/PerceivedComplexity,Metrics/AbcSize,Layout/EmptyLinesAroundAttributeAccessor,Style/RedundantSortBy,Layout/SpaceInLambdaLiteral,Layout/SpaceAroundEqualsInParameterDefault,Layout/EndOfLine,Lint/AmbiguousBlockAssociation,Lint/AmbiguousOperator,Layout/EmptyLinesAroundExceptionHandlingKeywords,Style/RedundantPercentQ,Layout/SpaceBeforeFirstArg,Lint/UnreachableCode,Lint/RedundantStringCoercion,Style/EachForSimpleLoop,Lint/RedundantWithIndex,Layout/CommentIndentation,Layout/DotPosition,Lint/UselessSetterCall,Lint/EmptyConditionalBody,Style/ComparableClamp,Style/RedundantFreeze,Lint/LiteralInInterpolation,Lint/EmptyBlock,Lint/DuplicateMagicComment,Style/NilLambda,Lint/UselessMethodDefinition,Lint/SelfAssignment,Layout/AccessModifierIndentation,Layout/CaseIndentation,Style/RedundantSelf,Lint/UselessTimes,Layout/EmptyLinesAroundAccessModifier,Lint/ToJSON,Security/YAMLLoad,Style/StabbyLambdaParentheses,Lint/StructNewOverride,Lint/Loop,Style/BlockComments,Layout/BeginEndAlignment,Style/GlobalStdStream,Style/EmptyElse,Layout/EmptyLineBetweenDefs,Style/SelfAssignment,Style/SingleLineMethods,Style/PreferredHashMethods,Style/NumericLiteralPrefix,Security/Open,Security/JSONLoad,Style/Sample,Style/Attr,Style/MissingRespondToMissing,Style/HashLikeCase,Style/PercentQLiterals,Lint/PercentStringArray,Lint/MixedRegexpCaptureTypes,Style/NestedParenthesizedCalls,Style/StringLiteralsInInterpolation,Style/BarePercentLiterals,Lint/RequireParentheses,Style/CaseEquality,Style/RedundantException,Naming/AsciiIdentifiers,Lint/ErbNewArguments,Lint/OrderedMagicComments"

cargo build --release --manifest-path "$ROOT/Cargo.toml" --quiet

# Normalize both outputs to "file:line:col: Cop: message" (headers folded in,
# [Correctable] tags stripped, absolute paths trimmed to the target-relative).
# Backticks go too: rubocop's simple formatter renders `...` spans as colored
# text (stripping the backticks under --no-color) — presentation, not message.
normalize() {
  awk -v strip="$1" '
    /^== .* ==$/ { f = substr($0, 4, length($0) - 6); sub(strip, "", f); next }
    /^[A-Z]:/ {
      line = $0
      sub(/^[A-Z]: */, "", line)
      gsub(/\[Correctable\] /, "", line)
      gsub(/`/, "", line)
      printf "%s:%s\n", f, line
    }
  ' | sort
}

# A corpus whose config `plugins:`-requires gems we don't install carries a
# cleaned copy (.rubocop_bench.yml); both sides must use the same one.
CFG=".rubocop.yml"
[ -f "$TARGET/.rubocop_bench.yml" ] && CFG=".rubocop_bench.yml"
# Both sides get --only: rubocop force-enables the listed cops (even under
# DisabledByDefault configs like rails'), so ours must too.
(cd "$TARGET" && "$BIN" --only "$COPS" . "$CFG") | normalize "^\./" > "$WORK/ours.txt" || true
(cd "$TARGET" && rubocop -c "$CFG" --only "$COPS" --cache false -f simple --no-color . 2>/dev/null) \
  | normalize "^\./" > "$WORK/theirs.txt" || true

if diff -u "$WORK/theirs.txt" "$WORK/ours.txt"; then
  echo "PARITY: $(wc -l < "$WORK/ours.txt" | tr -d ' ') offense lines identical on $TARGET"
else
  echo "DIVERGED (see diff above; - = rubocop only, + = oxidecop only)" >&2
  exit 1
fi
