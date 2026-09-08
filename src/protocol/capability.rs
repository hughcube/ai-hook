use super::event::HookEvent;
use super::input::Platform;

// ---------------------------------------------------------------------------
// 形状(shape)枚举:能力矩阵的第三维。
//
// 早期的矩阵只有 `gate: bool` / `ask: bool` / … 六个布尔位,回答的是
// "这个 (宿主, 事件) 有没有这条通道"。但真实协议里**同样有通道的两件事,
// 写法可能完全不同**,布尔位无法表达,于是形状被硬编码进 `output.rs` 的
// 平台 if-else 分支里 —— 这正是若干个线上缺陷的来源:
//
//   * CodeBuddy / WorkBuddy 的 Stop「继续」:官方文档写 `continue: false`,
//     但实现(`dist/codebuddy.js` 2.147.0 的 `parseHookOutput` +
//     `SessionHookManager.executeStopHooks`)只认 `blocking === true`,而
//     `continue: false` 不产生 blocking → 变成空操作。正确形状是
//     `decision: "block"`。
//   * opencode 桥(`opencode-claude-hooks` 0.1.0)根本不解析 JSON 决策,
//     `tool.execute.before` 只认 `exitCode === 2` → 阻断必须走退出码。
//
// 所以矩阵现在直接声明"用哪种形状表达",`output.rs` 只做查表,不再有
// 平台分支。新增一个宿主 = 填一张表,而不是再写一层 if-else。
// ---------------------------------------------------------------------------

/// 一个 (宿主, 事件) 上"拒绝 / 阻断"该怎么写。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyShape {
    /// 该事件没有阻断通道(能力矩阵 NONE)。
    None,
    /// `hookSpecificOutput.permissionDecision: "deny"` + `permissionDecisionReason`。
    /// Claude 家族的 PreToolUse(以及 ai-hook 未建模事件的尽力而为形态)。
    PermissionDecision,
    /// `hookSpecificOutput.decision:{behavior:"deny",message}`。
    /// Claude Code / Codex 的 PermissionRequest。
    BehaviorDeny,
    /// 顶层 `{"decision":"block","reason"}`。
    /// Claude 家族大多数事件 + Codex 的 Stop / UserPromptSubmit / PostToolUse。
    TopLevelBlock,
    /// `{"continue":false,"reason"}`。
    /// CodeBuddy / WorkBuddy(官方已废弃 `decision:"block"`,实现只认这个)
    /// 与 Codex 的 PreCompact。
    ContinueFalse,
    /// 顶层 `{"decision":"deny","reason"}`。Antigravity / Gemini CLI。
    HostDecisionDeny,
    /// 宿主不读任何 JSON 决策字段,只能靠退出码 2(原因写 stderr)。
    /// 目前只有 opencode 桥(`src/executor.ts`:`const blocked = exitCode === 2`)。
    ExitCode2,
}

/// "向用户确认"该怎么写。协议里只有 Claude 家族有真正的 ask 通道。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskShape {
    /// 协议没有 ask(Codex 官方证实会 fail-open;Gemini 协议无 ask;
    /// opencode 桥未实现)。confirm 一律降级为 GUI 弹窗或 fail-closed 拒绝。
    None,
    /// `hookSpecificOutput.permissionDecision: "ask"` + reason。
    PermissionAsk,
    /// Antigravity 的 `{"decision":"force_ask","reason"}`
    /// (忽略会话里缓存的 "Always Allow")。
    ForceAsk,
}

/// "把文本交给模型"该怎么写。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectShape {
    /// 没有模型上下文通道。
    None,
    /// `hookSpecificOutput.additionalContext`(Claude 家族 / Codex / Gemini)。
    AdditionalContext,
    /// Antigravity 的 `{"injectSteps":[{"ephemeralMessage":…}]}`,
    /// 只在 PreInvocation / PostInvocation 上开放。
    InjectSteps,
}

/// "改写工具入参"该怎么写。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutateShape {
    /// 没有改参通道(Antigravity 官方 PreToolUse 输出字段只有
    /// `decision` / `reason` / `permissionOverrides`)。
    None,
    /// `hookSpecificOutput.updatedInput`(必须配 `permissionDecision:"allow"`)。
    /// CodeBuddy 额外双发 `modifiedInput`(其实现两条路径各读一个键)。
    UpdatedInput,
    /// Gemini CLI 的 `hookSpecificOutput.tool_input`
    /// (官方:"merges with and overrides the model's arguments")。
    ToolInput,
}

/// "替换工具结果"该怎么写。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceShape {
    /// 没有替换通道。
    None,
    /// `hookSpecificOutput.updatedToolOutput`(Claude 家族;
    /// 内置工具要求值匹配工具输出形状,否则被忽略)。
    UpdatedToolOutput,
    /// 宿主没有替换字段,只能借阻断形状把文本当 reason 交给模型:
    /// Codex(`AsReason(TopLevelBlock)`,官方:`updatedMCPToolOutput`
    /// "parsed but not supported yet",feedback 即替换结果)与
    /// Gemini AfterTool(`AsReason(HostDecisionDeny)`,官方:deny 后
    /// "reason replaces the tool result sent back to the model")。
    AsReason(DenyShape),
}

/// Stop 类事件上"别停下"该怎么写。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowShape {
    /// 该事件没有控制流通道。
    None,
    /// `{"decision":"block","reason"}` —— Claude Code / Codex /
    /// CodeBuddy / WorkBuddy 的"继续"。
    /// 注意 CodeBuddy 的官方 hooks.md 写的是 `continue: false`,但那是
    /// **错的**:见文件头对 `parseHookOutput` / `executeStopHooks` 的取证。
    BlockDecision,
    /// Antigravity 的 `{"decision":"continue","reason"}`
    /// (官方:"Set to `"continue"` to prevent the agent from stopping…
    /// Any other value allows the stop")。
    ContinueDecision,
    /// Gemini CLI AfterAgent 的 `{"decision":"deny","reason"}`
    /// (官方:"reject the response and force a retry")。
    RetryDecision,
}

/// What a (platform, event) pair can actually express to the host.
///
/// Every field is either a documented host capability or — where the official
/// docs and the shipped implementation disagree — the shape the
/// **implementation** actually honours (see the file header). Claiming a
/// capability the host cannot express is worse than dropping it: an ignored
/// output is a silent ALLOW, so the matrix errs toward `None`.
///
/// 官网出处(逐条可核对):
/// - Claude Code  `https://code.claude.com/docs/en/hooks`
///   (Decision control 表 / 各事件 xx decision control 节)
/// - Codex CLI    `https://learn.chatgpt.com/docs/hooks`
///   (Common output fields / 各事件 Output 段)
/// - Gemini CLI   `https://geminicli.com/docs/hooks/reference/`
///   (Common output fields / BeforeTool / AfterTool / BeforeAgent / AfterAgent)
/// - Antigravity  `https://antigravity.google/docs/hooks/`
///   (Supported Events / 各事件 Output Fields)
/// - CodeBuddy    `@tencent-ai/codebuddy-code` 随包文档
///   `dist/web-ui/docs/cn/cli/hooks.md` + 随包实现 `dist/codebuddy.js`
/// - OpenCode     `https://github.com/magarcia/opencode-claude-hooks`
///   (README 的 Exit codes 段 + `src/executor.ts` / `src/index.ts`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// 该事件能否**真正拦住**一个动作。
    ///
    /// 与 [`Self::deny`] 是两个独立判断:`decision:"block"` 在 PostToolUse 上
    /// 只是把 reason 附加到工具结果旁(工具已跑完,拦不住),而同样的形状在
    /// UserPromptSubmit / PreCompact 上会真的阻止处理。置 false 时引擎会在
    /// stderr 提示"该事件没有阻断位",但仍按拒绝输出 —— 宿主最多忽略,
    /// 不会读成放行。
    pub gate: bool,
    pub deny: DenyShape,
    pub ask: AskShape,
    pub inject: InjectShape,
    /// 有 `systemMessage` 通道:文本**只展示给用户**,不进模型上下文。
    /// inject 不可用时会把规则要注入的文本降级到这里(并告警)。
    pub notify_user: bool,
    pub mutate_input: MutateShape,
    pub replace_output: ReplaceShape,
    pub flow: FlowShape,
}

impl Capabilities {
    /// 全通道关闭(未建模事件 / 宿主不消费输出的事件)。
    pub const NONE: Self = Self {
        gate: false,
        deny: DenyShape::None,
        ask: AskShape::None,
        inject: InjectShape::None,
        notify_user: false,
        mutate_input: MutateShape::None,
        replace_output: ReplaceShape::None,
        flow: FlowShape::None,
    };

    /// 规则侧最常用的两个别名,避免调用方到处写 `matches!`。
    #[must_use]
    pub const fn can_inject(&self) -> bool {
        !matches!(self.inject, InjectShape::None)
    }

    #[must_use]
    pub const fn can_ask(&self) -> bool {
        !matches!(self.ask, AskShape::None)
    }

    #[must_use]
    pub const fn can_mutate(&self) -> bool {
        !matches!(self.mutate_input, MutateShape::None)
    }

    #[must_use]
    pub const fn can_replace(&self) -> bool {
        !matches!(self.replace_output, ReplaceShape::None)
    }

    #[must_use]
    pub const fn can_flow(&self) -> bool {
        !matches!(self.flow, FlowShape::None)
    }

    const fn new(
        deny: DenyShape,
        ask: AskShape,
        inject: InjectShape,
        notify_user: bool,
        mutate_input: MutateShape,
        replace_output: ReplaceShape,
        flow: FlowShape,
    ) -> Self {
        Self {
            gate: false,
            deny,
            ask,
            inject,
            notify_user,
            mutate_input,
            replace_output,
            flow,
        }
    }

    /// 把该事件标记为"能真正拦住动作"(门禁类事件)。
    const fn gated(mut self) -> Self {
        self.gate = true;
        self
    }

    /// 只有阻断通道、且该阻断确实会拦住动作的最小门禁(压缩门禁)。
    const fn gate_only(deny: DenyShape) -> Self {
        Self::new(
            deny,
            AskShape::None,
            InjectShape::None,
            false,
            MutateShape::None,
            ReplaceShape::None,
            FlowShape::None,
        )
        .gated()
    }
}

/// Static capability matrix.
///
/// Implemented as a plain `match` so it compiles to a jump table / constant
/// folding — the hook hot path must not pay for the abstraction.
#[must_use]
pub fn capabilities(platform: Platform, event: HookEvent) -> Capabilities {
    use AskShape as A;
    use DenyShape as D;
    use FlowShape as F;
    use HookEvent as E;
    use InjectShape as I;
    use MutateShape as M;
    use Platform as P;
    use ReplaceShape as R;

    match (platform, event) {
        // ------------------------------------------------------------------
        // Pre-tool gate: the only event where all five primitives can appear.
        // ------------------------------------------------------------------
        (P::ClaudeCode, E::PreToolUse) => Capabilities::new(
            D::PermissionDecision,
            A::PermissionAsk,
            I::AdditionalContext,
            true,
            M::UpdatedInput,
            R::None,
            F::None,
        )
        .gated(),
        // opencode 桥:README 的 Exit codes 段只定义 `2 = Block/deny`,
        // `src/index.ts` 的 `tool.execute.before` 只判 `result.blocked`
        // (来自 `executor.ts` 的 `exitCode === 2`),**从不读
        // permissionDecision**;`additionalContext` 在该分支也没有被消费。
        // 唯一被消费的 JSON 是 `updatedInput`。
        (P::OpenCode, E::PreToolUse) => Capabilities::new(
            D::ExitCode2,
            A::None,
            I::None,
            false,
            M::UpdatedInput,
            R::None,
            F::None,
        )
        .gated(),
        // Codex: 官方 `permissionDecision:"ask"` 是 "parsed but not supported
        // yet. Codex marks the hook run as failed, reports the error, and
        // continues the tool call." → 发 ask 等于静默放行,通道必须关。
        (P::Codex, E::PreToolUse) => Capabilities::new(
            D::PermissionDecision,
            A::None,
            I::AdditionalContext,
            true,
            M::UpdatedInput,
            R::None,
            F::None,
        )
        .gated(),
        (P::CodeBuddy | P::WorkBuddy, E::PreToolUse) => Capabilities::new(
            D::PermissionDecision,
            A::PermissionAsk,
            I::AdditionalContext,
            true,
            M::UpdatedInput,
            R::None,
            F::None,
        )
        .gated(),
        // Antigravity PreToolUse: 官方输出字段表
        // (antigravity.google/docs/hooks/)只有 `decision` / `reason` /
        // `permissionOverrides` —— 没有 additionalContext、没有改参通道。
        // 任何改写形态(如 `overwrite`)都未被官方文档记载,发出去只会让宿主
        // 按 `decision:"allow"` 放行**原始**参数,规则却以为改写成功了 ——
        // 比"丢弃并告警"危险得多。
        (P::Antigravity, E::PreToolUse) => Capabilities::new(
            D::HostDecisionDeny,
            A::ForceAsk,
            I::None,
            false,
            M::None,
            R::None,
            F::None,
        )
        .gated(),
        // Gemini BeforeTool: 官方 Output Fields 只有 `decision` / `reason` /
        // `hookSpecificOutput.tool_input` / `continue`;没有
        // `additionalContext`(官方 `systemMessage` 的定义是 "Displayed
        // immediately to the user in the terminal",是给用户的,不能顶替
        // inject)。
        (P::Gemini, E::BeforeTool) => Capabilities::new(
            D::HostDecisionDeny,
            A::None,
            I::None,
            true,
            M::ToolInput,
            R::None,
            F::None,
        )
        .gated(),
        (P::Generic, E::PreToolUse) => Capabilities::new(
            D::PermissionDecision,
            A::None,
            I::AdditionalContext,
            true,
            M::UpdatedInput,
            R::None,
            F::None,
        )
        .gated(),

        // ------------------------------------------------------------------
        // Post-tool: nothing can be undone; only feedback is possible.
        // ------------------------------------------------------------------
        (P::ClaudeCode | P::CodeBuddy | P::WorkBuddy | P::Generic, E::PostToolUse) => {
            Capabilities::new(
                D::TopLevelBlock,
                A::None,
                I::AdditionalContext,
                true,
                M::None,
                R::UpdatedToolOutput,
                F::None,
            )
        }
        // Codex: 官方 `decision:"block"` 不撤销已执行的命令,而是
        // "replaces the tool result with that feedback";
        // `updatedToolOutput` / `updatedMCPToolOutput` 官方写明
        // "parsed but not supported yet" → 替换只能借 block 的 reason。
        (P::Codex, E::PostToolUse) => Capabilities::new(
            D::TopLevelBlock,
            A::None,
            I::AdditionalContext,
            true,
            M::None,
            R::AsReason(D::TopLevelBlock),
            F::None,
        ),
        // Antigravity PostToolUse 输出固定 `{}`:什么都不收。
        (P::Antigravity, E::PostToolUse) => Capabilities::NONE,
        // Gemini AfterTool: 官方 `decision:"deny"` + reason 隐藏真实输出并
        // **成为**模型看到的结果;`hookSpecificOutput.additionalContext`
        // 追加到结果之后。两者可组合。
        (P::Gemini, E::AfterTool) => Capabilities::new(
            D::HostDecisionDeny,
            A::None,
            I::AdditionalContext,
            true,
            M::None,
            R::AsReason(D::HostDecisionDeny),
            F::None,
        ),

        // ------------------------------------------------------------------
        // PostToolUseFailure: 工具已跑完(且失败),没有 undo,只能反馈。
        //   * Claude Code 官方 Decision control 表把它归入顶层 decision 组,
        //     其事件节只文档化 `additionalContext`。
        //   * Codex 官方事件表里**没有**这个事件(只有 PreToolUse /
        //     PermissionRequest / PostToolUse / PreCompact / PostCompact /
        //     UserPromptSubmit / SubagentStop / Stop / Interrupt /
        //     SessionStart / SubagentStart / SessionEnd)→ 不声明能力,
        //     否则矩阵会暗示一个并不存在的门禁点。
        //   * CodeBuddy / WorkBuddy 官方事件表同样没有它(随包实现里的
        //     `executePostToolUseFailureHooks` 只取 additionalContext,
        //     不发任何阻断)→ 同理置 NONE。
        //   * opencode 桥 `index.ts` 在 `tool.execute.after` 里调用
        //     handlePostToolUseFailure 后丢弃返回值 → NONE。
        // ------------------------------------------------------------------
        (P::ClaudeCode | P::Generic, E::PostToolUseFailure) => Capabilities::new(
            D::TopLevelBlock,
            A::None,
            I::AdditionalContext,
            true,
            M::None,
            R::None,
            F::None,
        ),

        // ------------------------------------------------------------------
        // Prompt gate. 没有任何宿主的 UserPromptSubmit 提供 ask 通道,
        // confirm 一律走 ai-hook GUI(不可用则 fail-closed)。
        // ------------------------------------------------------------------
        (P::ClaudeCode | P::Codex | P::Generic, E::UserPromptSubmit) => Capabilities::new(
            D::TopLevelBlock,
            A::None,
            I::AdditionalContext,
            true,
            M::None,
            R::None,
            F::None,
        )
        .gated(),
        // CodeBuddy / WorkBuddy 官方:UserPromptSubmit 用
        // `{"continue": false, "reason": …}` 阻断(随包实现
        // `executeUserPromptSubmitHooks` 是 `!ea.allowed → throw`,
        // `continue: false` 确实会置 allowed=false → 有效)。
        (P::CodeBuddy | P::WorkBuddy, E::UserPromptSubmit) => Capabilities::new(
            D::ContinueFalse,
            A::None,
            I::AdditionalContext,
            true,
            M::None,
            R::None,
            F::None,
        )
        .gated(),
        // Gemini BeforeAgent: 官方 `decision:"deny"` 阻断本轮并丢弃用户消息;
        // `hookSpecificOutput.additionalContext` 追加到本轮 prompt。
        (P::Gemini, E::BeforeAgent) => Capabilities::new(
            D::HostDecisionDeny,
            A::None,
            I::AdditionalContext,
            true,
            M::None,
            R::None,
            F::None,
        )
        .gated(),

        // ------------------------------------------------------------------
        // Turn end: the only decision is "keep going".
        // Gemini has no Stop event; AfterAgent's `decision:"deny"` rejects the
        // response and forces a retry, which is the same "keep going" intent.
        // ------------------------------------------------------------------
        // Claude Code 官方:Stop / SubagentStop 走顶层 `decision:"block"`,
        // 且 "**also accept** hookSpecificOutput.additionalContext for
        // non-error feedback that continues the conversation"。
        // Codex 官方:Stop / SubagentStop 用 `{"decision":"block","reason"}`
        // ("it tells Codex to continue and automatically creates a new
        // continuation prompt");`continue: false` 在 Codex 的含义恰好相反
        // ("If false, marks that hook run as stopped")。
        // CodeBuddy / WorkBuddy:官方 hooks.md 写 `continue: false`,但随包
        // 实现要求 `blocking === true`(只有 `decision:"block"` /
        // permissionDecision deny / 退出码 2 会置位);`continue: false` 只置
        // `allowed=false`,最终落到 warn "Stop hook failed non-blockingly;
        // not continuing" → 规则要的"继续"完全丢失。故用 BlockDecision。
        // Claude Code 官方 Decision control 表原文:"Stop and SubagentStop
        // **also accept** hookSpecificOutput.additionalContext for non-error
        // feedback that continues the conversation" —— 两个事件都有。
        (P::ClaudeCode, E::Stop | E::SubagentStop) => Capabilities::new(
            D::TopLevelBlock,
            A::None,
            I::AdditionalContext,
            true,
            M::None,
            R::None,
            F::BlockDecision,
        ),
        // Codex 的 Stop / SubagentStop 官方只说 "JSON on stdout supports
        // Common output fields",而 common fields 里只有 `systemMessage`
        // —— 没有 additionalContext,不能声称模型上下文通道。
        // CodeBuddy / WorkBuddy 官方 hooks.md 的 Stop·SubagentStop 节同样
        // 只给 `continue: false` + `reason`,未记载 additionalContext,
        // 随包实现也只消费 `message` —— 保守置 None,注入文本降级到
        // systemMessage。
        (P::Codex | P::CodeBuddy | P::WorkBuddy | P::Generic, E::Stop | E::SubagentStop) => {
            Capabilities::new(
                D::TopLevelBlock,
                A::None,
                I::None,
                true,
                M::None,
                R::None,
                F::BlockDecision,
            )
        }
        (P::Antigravity, E::Stop | E::SubagentStop) => Capabilities::new(
            D::HostDecisionDeny,
            A::None,
            I::None,
            false,
            M::None,
            R::None,
            F::ContinueDecision,
        ),
        (P::Gemini, E::AfterAgent) => Capabilities::new(
            D::HostDecisionDeny,
            A::None,
            I::None,
            true,
            M::None,
            R::None,
            F::RetryDecision,
        ),

        // ------------------------------------------------------------------
        // Session start: advisory context only (never blocks).
        // opencode 桥虽然注册了 SessionStart,但 `index.ts` 里
        // `await handleSessionStart(ctx, false)` 丢弃了返回的
        // additionalContext → 该通道实际无效。
        // ------------------------------------------------------------------
        (
            P::ClaudeCode | P::Codex | P::CodeBuddy | P::WorkBuddy | P::Gemini | P::Generic,
            E::SessionStart,
        ) => Capabilities::new(
            D::None,
            A::None,
            I::AdditionalContext,
            true,
            M::None,
            R::None,
            F::None,
        ),
        // Claude 家族的 SubagentStart:官方文档只给
        // `hookSpecificOutput.additionalContext`。
        // CodeBuddy / WorkBuddy 官方事件表没有 SubagentStart;随包实现
        // (`executeSubagentStartHooks`)虽然派发了该事件,但**完全不使用**
        // hook 输出 → 不声明能力。
        (P::ClaudeCode | P::Codex | P::Generic, E::SubagentStart) => Capabilities::new(
            D::None,
            A::None,
            I::AdditionalContext,
            true,
            M::None,
            R::None,
            F::None,
        ),

        // ------------------------------------------------------------------
        // Antigravity invocation hooks: the only place it accepts context
        // (`injectSteps`). Pre/Post cannot be told apart — the official stdin
        // schema is identical for both (`invocationNum` + `initialNumSteps`),
        // and payloads carry no event name, so `input.rs` classifies both as
        // `PreInvocation`.
        //
        // PostInvocation 的 `terminationBehavior`(`force_continue` /
        // `terminate`)刻意不建模为 flow:要发它必须能确定事件是
        // PostInvocation,而 payload 无法区分,且 PreInvocation 不记载该字段
        // —— 在那里发属于未定义行为。AGY 的"别停下"只在 Stop 上表达。
        // ------------------------------------------------------------------
        (P::Antigravity, E::PreInvocation | E::PostInvocation) => Capabilities::new(
            D::None,
            A::None,
            I::InjectSteps,
            false,
            M::None,
            R::None,
            F::None,
        ),

        // Gemini 的提示类事件:官方明确 "Flow-control fields are ignored",
        // 只有 `systemMessage`(显示给用户)。声明 inject 会让规则以为文本
        // 进了模型上下文,故 inject=None、notify_user=true。
        (P::Gemini, E::PreCompress | E::SessionEnd) => {
            Capabilities::new(D::None, A::None, I::None, true, M::None, R::None, F::None)
        }

        // ------------------------------------------------------------------
        // Permission request: allow / deny the pending approval prompt.
        //   * Claude Code / Codex:`hookSpecificOutput.decision.{behavior,
        //     message}`(官方:message "For "deny" only")。两者都没有
        //     additionalContext 通道,只有 systemMessage。
        //   * opencode 桥的 `permission.ask` 读的是
        //     `result.permissionDecision`(不是 `decision.behavior`),
        //     且只处理 allow / deny。
        // ------------------------------------------------------------------
        (P::ClaudeCode | P::Codex, E::PermissionRequest) => Capabilities::new(
            D::BehaviorDeny,
            A::None,
            I::None,
            true,
            M::None,
            R::None,
            F::None,
        )
        .gated(),
        (P::OpenCode, E::PermissionRequest) => Capabilities::new(
            D::PermissionDecision,
            A::None,
            I::None,
            false,
            M::None,
            R::None,
            F::None,
        )
        .gated(),

        // ------------------------------------------------------------------
        // Compaction gate: 形状随宿主不同,由矩阵直接声明。
        //   * Claude Code:官方 Decision control 表把 PreCompact 列入顶层
        //     `decision:"block"` 组;且 "Claude Code discards a PreCompact
        //     hook's systemMessage and continue fields" → notify_user=false。
        //   * Codex:官方 "If a matching PreCompact hook returns
        //     `continue: false`, Codex stops before compacting."
        //   * CodeBuddy / WorkBuddy:官方只记载退出码 2 阻止压缩,
        //     `continue: false` 是其通用阻断形态。
        // ------------------------------------------------------------------
        (P::ClaudeCode, E::PreCompact) => Capabilities::gate_only(D::TopLevelBlock),
        (P::Codex | P::CodeBuddy | P::WorkBuddy, E::PreCompact) => {
            Capabilities::gate_only(D::ContinueFalse)
        }

        // ------------------------------------------------------------------
        // 明确无通道的事件(官方文档 "None. No decision control."):
        // Setup / SessionEnd(Claude 家族)/ PostCompact / Notification …
        // Setup 在 Claude Code 上是:"On every exit code, Claude Code discards
        // a Setup hook's JSON output fields, such as systemMessage, continue,
        // and hookSpecificOutput.additionalContext。"
        // ------------------------------------------------------------------

        // Anything unmodelled: observing is fine, deciding is not.
        _ => Capabilities::NONE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_ask_is_closed_because_it_fails_open() {
        // Official (learn.chatgpt.com/docs/hooks): `permissionDecision:"ask"`
        // is "parsed but not supported yet. Codex marks the hook run as
        // failed, reports the error, and continues the tool call." Emitting an
        // ask would silently ALLOW the very call the rule wanted reviewed.
        assert!(!capabilities(Platform::Codex, HookEvent::PreToolUse).can_ask());
        // The gate itself still works: deny + non-empty reason is honored.
        assert!(capabilities(Platform::Codex, HookEvent::PreToolUse).gate);
        // UserPromptSubmit has no protocol ask on any host.
        assert!(!capabilities(Platform::Codex, HookEvent::UserPromptSubmit).can_ask());
        assert!(!capabilities(Platform::ClaudeCode, HookEvent::UserPromptSubmit).can_ask());
        // Claude Code / CodeBuddy / WorkBuddy do honor ask, even in bypass
        // mode: official PreToolUse decision control says `"ask" prompts the
        // user to confirm`, and "A hook's `"ask"` also forces a permission
        // prompt in auto mode" (both sentences verified present on
        // https://code.claude.com/docs/en/hooks as of 2026-09-08).
        assert!(capabilities(Platform::ClaudeCode, HookEvent::PreToolUse).can_ask());
        assert!(capabilities(Platform::CodeBuddy, HookEvent::PreToolUse).can_ask());
        assert!(capabilities(Platform::WorkBuddy, HookEvent::PreToolUse).can_ask());
        // Gemini has no ask in its protocol at all.
        assert!(!capabilities(Platform::Gemini, HookEvent::BeforeTool).can_ask());
        // The opencode bridge never implements ask in either handler.
        assert!(!capabilities(Platform::OpenCode, HookEvent::PreToolUse).can_ask());
    }

    #[test]
    fn codebuddy_keep_going_uses_block_decision_not_continue_false() {
        // 官方 hooks.md 写 `continue: false`,但随包实现(dist/codebuddy.js
        // 2.147.0)`executeStopHooks` 要求 `!allowed && message && blocking`,
        // 而 `parseHookOutput` 只在 `decision:"block"` / permissionDecision
        // deny / exit 2 时置 blocking;`continue: false` 只置 allowed=false。
        for p in [Platform::CodeBuddy, Platform::WorkBuddy] {
            let caps = capabilities(p, HookEvent::Stop);
            assert_eq!(caps.flow, FlowShape::BlockDecision);
            assert_eq!(caps.deny, DenyShape::TopLevelBlock);
        }
        // Claude Code / Codex / WorkBuddy 的 Stop 同样是 decision:"block"。
        assert_eq!(
            capabilities(Platform::ClaudeCode, HookEvent::Stop).flow,
            FlowShape::BlockDecision
        );
        // Antigravity / Gemini 各自一套。
        assert_eq!(
            capabilities(Platform::Antigravity, HookEvent::Stop).flow,
            FlowShape::ContinueDecision
        );
        assert_eq!(
            capabilities(Platform::Gemini, HookEvent::AfterAgent).flow,
            FlowShape::RetryDecision
        );
    }

    #[test]
    fn opencode_only_has_exit_code_deny() {
        // `src/executor.ts`: `const blocked = exitCode === 2`;
        // `src/index.ts` 的 `tool.execute.before` 只判 `result.blocked`。
        let pre = capabilities(Platform::OpenCode, HookEvent::PreToolUse);
        assert_eq!(pre.deny, DenyShape::ExitCode2);
        assert_eq!(pre.mutate_input, MutateShape::UpdatedInput);
        // permission.ask 分支读的是 permissionDecision,不是 decision.behavior。
        assert_eq!(
            capabilities(Platform::OpenCode, HookEvent::PermissionRequest).deny,
            DenyShape::PermissionDecision
        );
        // 桥没注册 Stop / UserPromptSubmit,且丢弃 tool.execute.after 的结果。
        assert_eq!(
            capabilities(Platform::OpenCode, HookEvent::Stop),
            Capabilities::NONE
        );
        assert_eq!(
            capabilities(Platform::OpenCode, HookEvent::UserPromptSubmit),
            Capabilities::NONE
        );
        assert_eq!(
            capabilities(Platform::OpenCode, HookEvent::PostToolUse),
            Capabilities::NONE
        );
    }

    #[test]
    fn events_without_a_post_tool_use_failure_are_inert() {
        // Codex / CodeBuddy / WorkBuddy 官方事件表都没有 PostToolUseFailure。
        for p in [
            Platform::Codex,
            Platform::CodeBuddy,
            Platform::WorkBuddy,
            Platform::OpenCode,
        ] {
            assert_eq!(
                capabilities(p, HookEvent::PostToolUseFailure),
                Capabilities::NONE,
                "{p} 不应声明 PostToolUseFailure 能力"
            );
        }
    }

    #[test]
    fn gemini_advisory_events_only_notify_the_user() {
        for e in [HookEvent::SessionEnd, HookEvent::PreCompress] {
            let caps = capabilities(Platform::Gemini, e);
            assert!(!caps.can_inject(), "{e:?} 没有模型上下文通道");
            assert!(caps.notify_user, "{e:?} 只有 systemMessage");
            assert_eq!(caps.deny, DenyShape::None);
        }
        // BeforeTool 也没有 additionalContext(官方 Output Fields 未列)。
        assert!(!capabilities(Platform::Gemini, HookEvent::BeforeTool).can_inject());
    }

    #[test]
    fn post_tool_use_failure_is_modelled() {
        // Claude Code lists PostToolUseFailure in the top-level `decision`
        // group and documents `hookSpecificOutput.additionalContext` for it.
        let caps = capabilities(Platform::ClaudeCode, HookEvent::PostToolUseFailure);
        assert_eq!(caps.deny, DenyShape::TopLevelBlock);
        assert!(caps.can_inject());
        assert!(!caps.can_replace());
        // 工具已经跑完(且失败),`decision:"block"` 只把 reason 反馈给模型,
        // 官方 exit code 2 表对 PostToolUse / PostToolUseFailure 均标 "Can
        // block? No" —— 所以它不是门禁位。
        assert!(!caps.gate);
        // PostToolUse 同理。
        assert!(!capabilities(Platform::ClaudeCode, HookEvent::PostToolUse).gate);
        assert!(!capabilities(Platform::CodeBuddy, HookEvent::PostToolUse).gate);
    }

    #[test]
    fn gemini_after_tool_and_after_agent_are_modelled() {
        let after_tool = capabilities(Platform::Gemini, HookEvent::AfterTool);
        assert!(after_tool.can_inject());
        assert_eq!(
            after_tool.replace_output,
            ReplaceShape::AsReason(DenyShape::HostDecisionDeny)
        );
        // AfterAgent: `decision:"deny"` rejects the response and forces a
        // retry — the Gemini form of "keep going".
        assert!(capabilities(Platform::Gemini, HookEvent::AfterAgent).can_flow());
        // BeforeAgent accepts additionalContext alongside the prompt.
        assert!(capabilities(Platform::Gemini, HookEvent::BeforeAgent).can_inject());
        // Codex 的替换借 block 的 reason。
        assert_eq!(
            capabilities(Platform::Codex, HookEvent::PostToolUse).replace_output,
            ReplaceShape::AsReason(DenyShape::TopLevelBlock)
        );
    }

    #[test]
    fn post_tool_use_cannot_gate() {
        assert!(!capabilities(Platform::ClaudeCode, HookEvent::PostToolUse).gate);
        assert!(!capabilities(Platform::Codex, HookEvent::PostToolUse).gate);
        assert!(!capabilities(Platform::Antigravity, HookEvent::PostToolUse).gate);
    }

    #[test]
    fn antigravity_has_no_additional_context() {
        assert!(!capabilities(Platform::Antigravity, HookEvent::PreToolUse).can_inject());
        assert_eq!(
            capabilities(Platform::Antigravity, HookEvent::PreInvocation).inject,
            InjectShape::InjectSteps
        );
        // 官方 PreToolUse 输出字段不含改参通道。
        assert!(!capabilities(Platform::Antigravity, HookEvent::PreToolUse).can_mutate());
    }

    #[test]
    fn unmodelled_events_are_inert() {
        assert_eq!(
            capabilities(Platform::ClaudeCode, HookEvent::Other),
            Capabilities::NONE
        );
        // Setup 在 Claude Code 上连 systemMessage 都会被丢弃。
        assert_eq!(
            capabilities(Platform::ClaudeCode, HookEvent::Setup),
            Capabilities::NONE
        );
    }
}
