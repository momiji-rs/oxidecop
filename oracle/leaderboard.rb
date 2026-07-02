#!/usr/bin/env ruby
# frozen_string_literal: true

# Fidelity leaderboard: for every cop oxidecop implements, run rubocop's OWN
# spec suite through the oracle and rank by pass-rate. This is the acceptance
# metric — "what % of rubocop's own tests do we pass, per cop", measured, not
# guessed.
#
# Fixtures are cached in spec_fixtures/ (fetched from rubocop v1.88.0).
# Usage: ruby leaderboard.rb

require 'open3'
require 'fileutils'

REF  = 'v1.88.0'
ROOT = File.expand_path('..', __dir__)
BIN  = File.join(ROOT, 'target/release/oxidecop')
DIR  = File.expand_path('spec_fixtures', __dir__)

system('cargo', 'build', '--release', '--manifest-path', File.join(ROOT, 'Cargo.toml'),
       out: File::NULL, err: File::NULL) unless File.exist?(BIN)
abort "build the binary first: cargo build --release" unless File.exist?(BIN)

# cop -> spec path within rubocop's repo (spec/rubocop/cop/<path>_spec.rb)
COPS = {
  'Style/NilComparison'              => 'style/nil_comparison',
  'Style/NumericPredicate'           => 'style/numeric_predicate',
  'Style/ZeroLengthPredicate'        => 'style/zero_length_predicate',
  'Style/RedundantReturn'            => 'style/redundant_return',
  'Style/NumericLiterals'            => 'style/numeric_literals',
  'Style/StringLiterals'             => 'style/string_literals',
  'Style/Documentation'              => 'style/documentation',
  'Style/FrozenStringLiteralComment' => 'style/frozen_string_literal_comment',
  'Naming/MethodName'                => 'naming/method_name',
  'Lint/NestedMethodDefinition'      => 'lint/nested_method_definition',
  'Style/SymbolProc'                 => 'style/symbol_proc',
  'Layout/LineLength'                => 'layout/line_length',
  'Layout/TrailingWhitespace'        => 'layout/trailing_whitespace',
  'Style/EvenOdd'                    => 'style/even_odd',
  'Lint/RandOne'                     => 'lint/rand_one',
  'Style/ArrayJoin'                  => 'style/array_join',
  'Lint/BooleanSymbol'               => 'lint/boolean_symbol',
  'Lint/BigDecimalNew'               => 'lint/big_decimal_new',
  'Style/Dir'                        => 'style/dir',
  'Style/StringChars'                => 'style/string_chars',
  'Style/NestedFileDirname'          => 'style/nested_file_dirname',
  'Lint/UriRegexp'                   => 'lint/uri_regexp',
  'Lint/UnifiedInteger'              => 'lint/unified_integer',
  'Lint/FlipFlop'                    => 'lint/flip_flop',
  'Style/Proc'                       => 'style/proc',
  'Lint/DuplicateCaseCondition'      => 'lint/duplicate_case_condition',
  'Lint/DuplicateElsifCondition'     => 'lint/duplicate_elsif_condition',
  'Style/ColonMethodDefinition'      => 'style/colon_method_definition',
  'Layout/LeadingEmptyLines'         => 'layout/leading_empty_lines',
  'Style/Strip'                      => 'style/strip',
  'Lint/TopLevelReturnWithArgument'  => 'lint/top_level_return_with_argument',
  'Security/Eval'                    => 'security/eval',
  'Style/VariableInterpolation'      => 'style/variable_interpolation',
  'Lint/EachWithObjectArgument'      => 'lint/each_with_object_argument',
  'Style/TrailingBodyOnModule'       => 'style/trailing_body_on_module',
  'Lint/RegexpAsCondition'           => 'lint/regexp_as_condition',
  'Lint/DuplicateRescueException'    => 'lint/duplicate_rescue_exception',
  'Style/TrailingBodyOnClass'        => 'style/trailing_body_on_class',
  'Lint/SafeNavigationWithEmpty'     => 'lint/safe_navigation_with_empty',
  'Style/RedundantCapitalW'          => 'style/redundant_capital_w',
  'Lint/HashCompareByIdentity'       => 'lint/hash_compare_by_identity',
  'Lint/NextWithoutAccumulator'      => 'lint/next_without_accumulator',
  'Layout/SpaceAfterColon'           => 'layout/space_after_colon',
  'Lint/MultipleComparison'          => 'lint/multiple_comparison',
  'Style/EmptyLambdaParameter'       => 'style/empty_lambda_parameter',
  'Layout/SpaceInsideArrayPercentLiteral' => 'layout/space_inside_array_percent_literal',
  'Style/IfUnlessModifierOfIfUnless' => 'style/if_unless_modifier_of_if_unless',
  'Style/EmptyBlockParameter'        => 'style/empty_block_parameter',
  'Lint/IdentityComparison'          => 'lint/identity_comparison',
  'Layout/SpaceInsideRangeLiteral'   => 'layout/space_inside_range_literal',
  'Style/DoubleCopDisableDirective'  => 'style/double_cop_disable_directive',
  'Style/ClassCheck'                 => 'style/class_check',
  'Naming/BlockParameterName'        => 'naming/block_parameter_name',
  'Style/ClassMethods'               => 'style/class_methods',
  'Style/TrailingBodyOnMethodDefinition' => 'style/trailing_body_on_method_definition',
  'Lint/UselessElseWithoutRescue'    => 'lint/useless_else_without_rescue',
  'Lint/ReturnInVoidContext'         => 'lint/return_in_void_context',
  'Style/MultilineBlockChain'        => 'style/multiline_block_chain',
  'Style/OptionalArguments'          => 'style/optional_arguments',
  'Style/RedundantFileExtensionInRequire' => 'style/redundant_file_extension_in_require',
  'Lint/TrailingCommaInAttributeDeclaration' => 'lint/trailing_comma_in_attribute_declaration',
  'Layout/ConditionPosition'         => 'layout/condition_position',
  'Naming/HeredocDelimiterNaming'    => 'naming/heredoc_delimiter_naming',
  'Style/MultilineWhenThen'          => 'style/multiline_when_then',
  'Naming/MethodParameterName'       => 'naming/method_parameter_name',
  'Style/MultilineIfModifier'        => 'style/multiline_if_modifier',
  'Layout/EmptyLinesAroundBeginBody' => 'layout/empty_lines_around_begin_body',
  'Layout/EmptyLinesAroundBlockBody' => 'layout/empty_lines_around_block_body',
  'Style/ClassVars'                  => 'style/class_vars',
  'Lint/NestedPercentLiteral'        => 'lint/nested_percent_literal',
  'Lint/PercentSymbolArray'          => 'lint/percent_symbol_array',
  'Style/MinMax'                     => 'style/min_max',
  'Style/TrailingMethodEndStatement' => 'style/trailing_method_end_statement',
  'Style/OptionalBooleanParameter'   => 'style/optional_boolean_parameter',
  'Layout/SpaceInsideStringInterpolation' => 'layout/space_inside_string_interpolation',
  'Layout/EmptyLinesAroundMethodBody' => 'layout/empty_lines_around_method_body',
  'Style/NestedTernaryOperator'      => 'style/nested_ternary_operator',
  'Layout/AssignmentIndentation'     => 'layout/assignment_indentation',
  'Lint/CircularArgumentReference'   => 'lint/circular_argument_reference',
  'Lint/BinaryOperatorWithIdenticalOperands' => 'lint/binary_operator_with_identical_operands',
  'Lint/InterpolationCheck'          => 'lint/interpolation_check',
  'Lint/FloatComparison'             => 'lint/float_comparison',
  'Layout/SpaceInsidePercentLiteralDelimiters' => 'layout/space_inside_percent_literal_delimiters',
  'Lint/EmptyWhen'                   => 'lint/empty_when',
  'Lint/InheritException'            => 'lint/inherit_exception',
  'Lint/ConstantDefinitionInBlock'   => 'lint/constant_definition_in_block',
  'Lint/ElseLayout'                  => 'lint/else_layout',
  'Layout/EmptyLinesAroundModuleBody' => 'layout/empty_lines_around_module_body',
  'Lint/DisjunctiveAssignmentInConstructor' => 'lint/disjunctive_assignment_in_constructor',
  'Lint/IneffectiveAccessModifier'   => 'lint/ineffective_access_modifier',
  'Lint/EmptyEnsure'                 => 'lint/empty_ensure',
  'Lint/EmptyExpression'             => 'lint/empty_expression',
  'Lint/UriEscapeUnescape'           => 'lint/uri_escape_unescape',
  'Style/UnpackFirst'                => 'style/unpack_first',
  'Style/RandomWithOffset'           => 'style/random_with_offset',
  'Lint/Debugger'                    => 'lint/debugger',
  'Style/NegatedIf'                  => 'style/negated_if',
  'Lint/EmptyFile'                   => 'lint/empty_file',
  'Layout/TrailingEmptyLines'        => 'layout/trailing_empty_lines',
  'Layout/InitialIndentation'        => 'layout/initial_indentation',
  'Style/NegatedWhile'               => 'style/negated_while',
  'Style/CharacterLiteral'           => 'style/character_literal',
  'Style/UnlessElse'                 => 'style/unless_else',
  'Lint/EmptyInterpolation'          => 'lint/empty_interpolation',
  'Lint/EnsureReturn'                => 'lint/ensure_return',
  'Style/EndBlock'                   => 'style/end_block',
  'Style/BeginBlock'                 => 'style/begin_block',
  'Naming/ConstantName'              => 'naming/constant_name',
  'Naming/ClassAndModuleCamelCase'   => 'naming/class_and_module_camel_case',
  'Naming/BinaryOperatorParameterName' => 'naming/binary_operator_parameter_name',
  'Lint/DuplicateRequire'            => 'lint/duplicate_require',
  'Style/StderrPuts'                 => 'style/stderr_puts',
  'Style/ColonMethodCall'            => 'style/colon_method_call',
  'Lint/EmptyClass'                  => 'lint/empty_class',
  'Lint/DeprecatedClassMethods'      => 'lint/deprecated_class_methods',
  'Layout/EmptyLineAfterMagicComment' => 'layout/empty_line_after_magic_comment',
  'Layout/EmptyLines'                => 'layout/empty_lines',
  'Style/EmptyLiteral'               => 'style/empty_literal',
  'Style/Semicolon'                  => 'style/semicolon',
  'Style/GlobalVars'                 => 'style/global_vars',
  'Layout/SpaceAfterComma'           => 'layout/space_after_comma',
  'Layout/SpaceBeforeSemicolon'      => 'layout/space_before_semicolon',
  'Layout/SpaceBeforeComma'          => 'layout/space_before_comma',
  'Layout/SpaceBeforeComment'        => 'layout/space_before_comment',
  'Lint/FloatOutOfRange'             => 'lint/float_out_of_range',
  'Style/SymbolLiteral'              => 'style/symbol_literal',
  'Lint/RescueException'             => 'lint/rescue_exception',
  'Style/WhenThen'                   => 'style/when_then',
  'Lint/DuplicateHashKey'            => 'lint/duplicate_hash_key',
  'Security/MarshalLoad'             => 'security/marshal_load',
  'Layout/SpaceAfterMethodName'      => 'layout/space_after_method_name',
  'Layout/SpaceAfterSemicolon'       => 'layout/space_after_semicolon',
  'Layout/SpaceAfterNot'             => 'layout/space_after_not',
  'Style/DefWithParentheses'         => 'style/def_with_parentheses',
  'Style/WhileUntilDo'               => 'style/while_until_do',
  'Style/MultilineIfThen'            => 'style/multiline_if_then',
  'Style/Not'                        => 'style/not'
}.freeze

FileUtils.mkdir_p(DIR)

def fetch(rel)
  local = File.join(DIR, "#{File.basename(rel)}_spec.rb")
  return local if File.exist?(local)

  url = "https://raw.githubusercontent.com/rubocop/rubocop/#{REF}/spec/rubocop/cop/#{rel}_spec.rb"
  out, st = Open3.capture2('curl', '-fsSL', url)
  if st.success? && !out.empty?
    File.write(local, out)
    warn "  fetched #{rel}"
    local
  else
    warn "  MISSING spec for #{rel}"
    nil
  end
end

rows = []
COPS.each do |cop, rel|
  spec = fetch(rel)
  next unless spec

  _out, err, = Open3.capture3({ 'ORACLE_QUIET' => '1' },
                              'ruby', File.expand_path('oracle.rb', __dir__), BIN, cop, spec)
  line = err.lines.find { |l| l.start_with?('SUMMARY') }
  next unless line

  _, name, total, aloc, afull, _dt, _dl, _df, skipped, fpass, ftotal = line.chomp.split("\t")
  rows << { cop: name, total: total.to_i, loc: aloc.to_i, full: afull.to_i, skipped: skipped.to_i,
            fpass: fpass.to_i, ftotal: ftotal.to_i }
end

# rank by FULL pass-rate across ALL rubocop spec examples for the cop
rows.sort_by! { |r| [-(r[:total].zero? ? 0 : r[:full].to_f / r[:total]), -r[:total]] }

puts
puts '════════════════════════ oxidecop fidelity leaderboard ════════════════════════'
puts format('  %-34s %8s %6s  %10s  %10s', 'cop', 'scored', 'skip', 'LOC', 'FULL')
puts '  ' + ('─' * 80)
tot_full = tot_all = tot_skip = 0
rows.each do |r|
  pct = r[:total].zero? ? 0 : (100.0 * r[:full] / r[:total])
  bar = '█' * (pct / 10).round
  fixcol = r[:ftotal].zero? ? '     —' : format('%3d/%-3d', r[:fpass], r[:ftotal])
  puts format('  %-34s %8d %6d  %4d/%-4d   %4d/%-4d  %s %5.0f%% %s',
              r[:cop], r[:total], r[:skipped], r[:loc], r[:total], r[:full], r[:total], fixcol, pct, bar)
  tot_full += r[:full]
  tot_all  += r[:total]
  tot_skip += r[:skipped]
  $fix_pass = ($fix_pass || 0) + r[:fpass]
  $fix_total = ($fix_total || 0) + r[:ftotal]
end
puts '  ' + ('─' * 80)
overall = tot_all.zero? ? 0 : (100.0 * tot_full / tot_all)
puts format('  %-34s %8d %6d  %10s   %4d/%-4d  %5.0f%%   FIX %d/%d',
            'TOTAL (representable examples)', tot_all, tot_skip, '', tot_full, tot_all, overall,
            $fix_pass || 0, $fix_total || 0)
puts "  (skipped = spec examples the harness can't faithfully represent; excluded from scoring)"
puts

# --assert: CI guardrail — anything short of 100% detection AND 100% FIX fails
if ARGV.include?('--assert')
  problems = []
  problems << "detection #{tot_full}/#{tot_all}" if tot_full != tot_all
  problems << "FIX #{$fix_pass}/#{$fix_total}" if ($fix_pass || 0) != ($fix_total || 0)
  abort("FIDELITY REGRESSION: #{problems.join(', ')}") if problems.any?
end
