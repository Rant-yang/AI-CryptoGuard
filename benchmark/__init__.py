"""benchmark/ —— 用现成的公开 benchmark 代替人工标注。

一句话：**没有标签就没有准确率，没有准确率就没有「有效性」的证明。**

这个包做四件事：

    scope.py        这些 benchmark 的标签，哪些我们能比、哪些压根不该比
    anonymize.py    跑分前的匿名化（benchmark 的命名直接就是答案）
    adapters.py     各家标签 -> 我们的统一格式
    eval.py         算 Precision / Recall / F1

第三方数据**不入库**：源码树在仓库外的 `../_benchmarks/`，
跑出来的标签与匿名树在 `benchmark/labels/`、`benchmark/_anon/`（已 gitignore）。
仓库里只有我们自己的适配代码。
"""
