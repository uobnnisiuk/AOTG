# AOTG

AI-Optimized Toolchain Generator は、機材と推論環境の情報をもとに構成候補を計画し、測定・検証して再現可能なキットを生成するプロジェクトです。

初回実装では、2種類のfixtureで環境manifestの検証からキット生成・検証までを実行できます。測定値は合成データです。ハードウェア検出は、利用者が指定したローカルOSの読み取り専用情報に限ります。

[MVP設計](docs/mvp.md) · [manifestスキーマ](schema/manifest.schema.json) · [基準ベンチのfixtureと測定設計](docs/benchmark.md)

## Mock dry-run

Python 3.11以上で、リポジトリのルートから実行します。実行時の外部依存はありません。

```sh
python -m aotg inspect --manifest tests/fixtures/linux-mock.json
python -m aotg plan --manifest tests/fixtures/linux-mock.json --output out/plan.json
python -m aotg bench --plan out/plan.json --output out/run.json
python -m aotg compare --run out/run.json --output out/decision.json
python -m aotg build-kit --run out/run.json --decision out/decision.json --output out/kit.json
python -m aotg verify-kit --kit out/kit.json --run out/run.json
```

Windows側の例には `tests/fixtures/windows-mock.json` を使えます。中断時は同じplanと前回のレポートを `bench --resume <前回レポート>` に指定し、新しい出力先に結果を保存できます。出力先には、試行記録を保存できるAOTG専用ディレクトリを使ってください。既存の結果ファイルがある場合は、別の出力先を指定します。

ローカルOSの読み取り専用検出は、Linuxで `python -m aotg inspect --adapter linux`、Windowsで `python -m aotg inspect --adapter windows` を使います。取得できない項目は `null` で示します。推論エンジン・モデル・API・OpenCodeの設定は自動取得の対象外です。LinuxのROCm欄はインストール情報から取得します。WindowsのVRAM容量とGPUランタイムは未取得です。公開リポジトリの環境サンプルは合成データです。

## 確認

```sh
python -m unittest discover -s tests -v
python -m compileall -q aotg tests
```
