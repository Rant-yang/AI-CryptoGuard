"""Build the reviewable, evidence-bounded competition presentation.

Requires python-pptx. The generated PPTX is a candidate, not a claim that
independent holdout, human review, or fresh-machine rehearsal has passed.
"""
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.util import Inches, Pt


HERE = Path(__file__).resolve().parent
OUT = HERE / "AI-CryptoGuard-答辩候选版.pptx"
NAVY = RGBColor(12, 22, 34)
PANEL = RGBColor(23, 38, 54)
CYAN = RGBColor(83, 223, 206)
GOLD = RGBColor(246, 193, 99)
RED = RGBColor(241, 105, 99)
WHITE = RGBColor(244, 248, 250)
MUTED = RGBColor(166, 187, 199)
FONT = "Microsoft YaHei"

prs = Presentation()
prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
# 网络评审材料须匿名。python-pptx 默认会留下模板作者元数据，生成时清空。
prs.core_properties.author = ""
prs.core_properties.last_modified_by = ""
prs.core_properties.title = "AI-CryptoGuard"
prs.core_properties.subject = ""
prs.core_properties.keywords = ""
prs.core_properties.comments = ""


def box(slide, x, y, w, h, fill=PANEL, radius=True):
    shape = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE if radius else MSO_SHAPE.RECTANGLE,
        Inches(x), Inches(y), Inches(w), Inches(h))
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill
    shape.line.fill.background()
    return shape


def words(slide, x, y, w, h, content, size=18, color=WHITE, bold=False,
          align=PP_ALIGN.LEFT):
    shape = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = shape.text_frame
    tf.clear()
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(.02)
    tf.margin_top = tf.margin_bottom = Inches(.02)
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    for i, line in enumerate(str(content).split("\n")):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.text = line
        p.alignment = align
        p.space_after = Pt(3)
        p.font.name = FONT
        p.font.size = Pt(size)
        p.font.bold = bold
        p.font.color.rgb = color
    return shape


def new_slide(title, kicker="AI-CryptoGuard · 复赛候选材料"):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    box(slide, 0, 0, 13.333, 7.5, NAVY, False)
    box(slide, .47, .42, .08, .65, CYAN, False)
    words(slide, .7, .37, 11.8, .8, title, 31, WHITE, True)
    words(slide, .7, 7.05, 10.8, .28, kicker, 10, MUTED)
    words(slide, 12.1, 7.04, .72, .3, f"{len(prs.slides):02d}", 10, MUTED,
          align=PP_ALIGN.RIGHT)
    return slide


def card(slide, x, y, w, h, heading, body, accent=CYAN, body_size=16):
    box(slide, x, y, w, h)
    box(slide, x, y, .07, h, accent, False)
    words(slide, x+.25, y+.18, w-.5, .4, heading, 20, accent, True)
    words(slide, x+.25, y+.71, w-.5, h-.9, body, body_size, WHITE)


# 1 — title
s = new_slide("AI-CryptoGuard", "全国密码技术竞赛 · 复赛 · 三人团队 · 候选演示稿")
words(s, .8, 1.5, 11.7, 1.2, "从多源证据到可解释的密码风险与抗量子迁移建议", 27, WHITE, True)
box(s, .8, 3.5, 11.7, 1.45)
words(s, 1.2, 3.73, 10.9, .95,
      "源码项目  →  风险与证据  →  用途判断  →  整改/迁移  →  中文报告", 22, CYAN)
words(s, .8, 5.55, 11.9, .85,
      "自研：证据融合、风险规则、AI 约束、凭据检测、评测与交互\n第三方：CryptoScan / cbom-scan / CrySentry 的底层扫描能力", 16, MUTED)

# 2 — product flow
s = new_slide("用户看见的是一个完整流程")
stages = [
    ("01 上传项目", "本地上传源码\nJava 可另给编译产物"),
    ("02 查看扫描", "快速扫描\n可选 Java 深度证据"),
    ("03 解释风险", "前置量子评估\n显式启用 AI 解读"),
    ("04 形成报告", "证据引用 / 未知项\n中文界面与离线 HTML"),
]
for i, (a, b) in enumerate(stages):
    card(s, .55 + i*3.18, 1.55, 2.94, 3.85, a, b, CYAN if i < 2 else GOLD, 17)
words(s, .78, 5.95, 11.8, .65,
      "缺工具、超时或模型失败会显示真实状态；保留已完成阶段的结果。", 18, MUTED)

# 3 — why fusion
s = new_slide("为什么需要统一证据层？")
card(s, .75, 1.55, 3.8, 3.92, "输入各说各话",
     "风险词义不同\n严重度和路径格式不同\n同一处调用可能重复上报", CYAN, 18)
card(s, 4.77, 1.55, 3.8, 3.92, "我们的处理",
     "归一化算法与文件位置\n按文件/算法/用途收口\n保留 E1、E2… 原始证据位置", GOLD, 18)
card(s, 8.79, 1.55, 3.8, 3.92, "输出有边界",
     "经典已破 ≠ Shor 可破\n不确定用途写 unknown\n不完整数据流标 partial", RED, 18)

# 4 — originality
s = new_slide("能力归属：把第三方和原创说清楚")
card(s, .8, 1.4, 5.65, 4.6, "第三方能力",
     "CryptoScan：源码模式扫描\ncbom-scan：密码资产清点\nCrySentry/Tai-e：Java 字节码分析", RED, 19)
card(s, 6.85, 1.4, 5.65, 4.6, "本项目原创",
     "统一入口与隔离调用\n证据融合 / 本地规则 / 凭据检测\n用途约束的 AI 解释 / 中文报告\n匿名化评测与阶段状态", CYAN, 17)
words(s, .88, 6.22, 11.8, .42,
      "CrySentry 以仓库外进程调用；其 LGPL-3.0 工具本体不放入主仓库。", 16, MUTED)

# 5 — Java deep
s = new_slide("Demo B：Java 深度证据，展示它真正增加了什么")
card(s, .75, 1.42, 5.6, 4.65, "公开故意不安全样例",
     "Random.nextBytes 生成密钥字节\nSecretKeySpec 构造密钥\nCrySentry 真实运行并定位两端\n产生独立弱随机密钥 Finding", CYAN, 17)
card(s, 6.7, 1.42, 5.83, 4.65, "证据诚实显示",
     "taint = partial\n只见来源与汇点，没有中间传播路径\n快速/深度/量子/AI 四阶段已跑通\n25 例算法专项无增益；7 例弱密钥专项有增益", GOLD, 17)
words(s, .86, 6.25, 11.6, .39,
      "预注册的 7 例弱密钥专项：深扫新增 4 个真阳性、1 个误报；不能替代全系统指标。", 15, MUTED)

# 6 — AI + quantum
s = new_slide("AI 不替规则库决定密码学事实")
card(s, .74, 1.38, 5.75, 4.78, "先由本地规则评估",
     "区分经典已破 / Shor / Grover\n公钥迁移必须看实际用途\n签名 → ML-DSA / SLH-DSA\n加密、协商 → ML-KEM", CYAN, 17)
card(s, 6.83, 1.38, 5.75, 4.78, "AI 只解释证据支持的内容",
     "判断用途并引用 E1/E2…\n指出证据不足和待核查事项\n给可执行整改步骤\n不得自行指定未经规则核验的算法", GOLD, 17)
words(s, .86, 6.35, 11.7, .35,
      "用途不能确定时写 unknown；X/Y/Z 时间窗口是用户假设，不是量子危机日期预测。", 15, MUTED)

# 7 — metrics
s = new_slide("评测：每个数字都带自己的口径")
rows = [
    ("开发语料 · 算法+凭据口径", "619 / 97 / 63", "86.5% / 90.8%", "非独立留出"),
    ("凭据专项 · 同批开发语料", "165 / 73 / 57", "69.3% / 74.3%", "专项仍待提高"),
    ("OWASP 首次 · 文件级", "219 / 27 / 40", "89.0% / 84.6%", "独立诊断；单位不同"),
    ("Java 弱密钥 · 7 例独立", "深扫 4 / 1 / 1", "80.0% / 80.0%", "单规则；非全系统"),
]
for i, (name, counts, scores, caveat) in enumerate(rows):
    y = 1.42 + i*1.16
    box(s, .72, y, 11.86, .97)
    words(s, .96, y+.16, 4.0, .53, name, 17, WHITE, True)
    words(s, 4.96, y+.16, 2.25, .53, counts, 16, MUTED)
    words(s, 7.18, y+.16, 2.36, .53, scores, 17, CYAN, True)
    words(s, 9.63, y+.16, 2.66, .53, caveat, 14, GOLD)
words(s, .82, 6.31, 11.75, .37,
      "列顺序：TP / FP / FN，P / R。历史 25 例为 77.8%/87.5%；当前同集重跑快/深均为 73.7%/87.5%。", 13, MUTED)

# 8 — privacy
s = new_slide("隐私、失败与修复边界")
card(s, .73, 1.47, 3.87, 4.77, "默认本地",
     "未明确启用 AI 不出网\n凭据只保留指纹/遮蔽值\n原始扫描和映射不入库", CYAN, 17)
card(s, 4.72, 1.47, 3.87, 4.77, "云端最小化",
     "白名单字段与敏感值脱敏\n不发送绝对路径、token 和 raw\n敏感项目用调用形状模式", GOLD, 17)
card(s, 8.71, 1.47, 3.87, 4.77, "候选修复",
     "只改临时副本\n正式扫描器前后复扫\n业务兼容仍需项目测试与人工复核", RED, 17)

# 9 — demos
s = new_slide("现场演示顺序：三段稳定故事")
card(s, .75, 1.45, 3.77, 4.67, "A · 密码/凭据",
     "上传自建公开样例\n展示 4 条 Finding、E 引用\n候选修复仅在临时副本", CYAN, 17)
card(s, 4.78, 1.45, 3.77, 4.67, "B · Java 深度",
     "已编译 jar + CrySentry\n展示 taint 首尾和 partial\n讲清底层引擎是第三方", GOLD, 17)
card(s, 8.8, 1.45, 3.77, 4.67, "C · 抗量子迁移",
     "RSA 签名与 ECDH 协商\n按用途分别走签名/KEM\n未知用途不给固定路线", CYAN, 17)
words(s, .85, 6.32, 11.6, .39,
      "网络不稳时用本地评估与离线 HTML；AI 阶段如 skipped，现场如实说明。", 15, MUTED)

# 10 — finish / open gates
s = new_slide("距离正式提交，还要补齐这些证明")
card(s, .85, 1.43, 11.65, 4.8, "冻结前验收清单",
     "① 新的同口径独立留出集；八类凭据分别核验\n"
     "② 当前 28 条算法 AI 结果的独立人工语义盲审\n"
     "③ 第三方项目 Repair→Verify 正向兼容性验证\n"
     "④ 异机部署、最终许可证/打包清单、两次全程彩排",
     GOLD, 20)
words(s, .88, 6.3, 11.5, .39,
      "已验证的就展示证据；未验证的明确写待完成。候选稿不能替代最终验收。", 15, MUTED)

prs.save(OUT)
print("slides=%d output=%s" % (len(prs.slides), OUT))
