# EVO-X3初号機: 2026-11-23の再開確認と認証・比較制御の準備

## 状態と範囲

本番停止を伴う新たな比較は未承認・未実行。新しい最適化試行は0件。
11月16日に承認された1回の起動診断は終了・消費済みであり、その承認・gate・結果を再利用しない。
今回の成果は実機の読み取り確認、隔離実装、検証と知見の保存であり、初号機Goalの完了ではない。

GitHub main `3a5d85c08c230c6c123da87abc61d21f21dcd2e0` とOpen PRを再確認した。
PR #30は起動診断、PR #31は比較runtimeの履歴で、いずれもDraftのまま。
今回の文書と隣接GUIソースは準備段階の追加記録であり、過去の実測記録を書き換えない。

## 読み取りで観測した事実

既存の検証済みSSH経路と読み取りpayloadを再利用し、2026-11-23 05:09:30 UTCに確認した。
保護対象19件の内容hashは前回の基準と一致し、推論エンジンの引数と実行ファイルのstat情報も一致した。
本番systemd unitはactive/exited、成功状態で、別に確認したnative推論プロセスも基準と一致した。
このunitはoneshotのためMainPID=0を推論エンジン不在と解釈しない。

この時点のMemAvailableは57,892,749,312 bytes、pswpoutは115、oom_killは0だった。
前回診断後のpswpout=108から増えているが、約1週間のどこで・何により増えたかは未検証。
AOTGの今回の調査に起因したと結論しない。次回の安全監視には新たな起点を使う。

モデル重みは読み取らず、GPU runtimeのロード、推論要求、サービス停止・切替は行っていない。
実行ファイル全体の再hash、現在のAPIのidle状態、開発課題の品質を新たに確認したものではない。
raw記録とWindows Jobのreceiptは私有領域に保存し、内部アドレス・認証情報・個人パスを公開しない。

## 問題・仮説・修正・検証

| 問題と仮説 | 隔離実装と比較条件 | 確認結果と限界 |
|---|---|---|
| 認証後に別のチャット返答を待つ設計では、所有者の離席に耐えない | 一つのPS5呼出しでpreview→Enter待機→再検証→1回のsudo enrollment→detached launcherへ進むGUI生成器 | 既定モードはlocal previewのみ。実PS5→WSL→無害なPython launcherでpreview成功、未承認実行を認証前に拒否。実gateの新規enrollは未実行 |
| PS5のnative境界で引用符を含むPython -cが壊れる過去の障害 | 既存の成功済みnumeric hex/to_bytes方式から新gate path/hashのみを生成し、任意commandを受け付けない | 無害なnative argv recorderに渡ったbytesが完全一致。受信文字列をデータとして構文解析した。SSH・sudo・bootstrapはこの試験で実行していない |
| PS7のPSModulePathをPS5が継承するとcmdlet autoloadが失敗する | PS5の子プロセスだけDesktop Modulesへ設定、hashは.NETで計算 | PS7-only module pathから開始した実PS5 5.1.26100.9818で成功。ユーザー/マシンの恒久環境や実行ポリシーは変更なし |
| 親監視と子handoffの同じ6410秒が別の起点から数えられる | 親にprearmの最大30秒を加え、watch6440秒＋cleanup15秒とする | 子が29.8秒遅れて開始する合成例で、子の期限前に親が打ち切らないことを確認。実機での全時間保証ではない |
| import対象10moduleだけを許可すると、同じroot内の固定catalogまで拒否する | 唯一の固定catalogについてpath/hash/descriptorの一致を別に要求 | extraファイル、pyc、別path/hash、欠落を拒否。任意追加ファイルを許す変更ではない |
| 既存OpenCodeが153,235,488 bytesで、一般sourceの64MiB読取上限を超える | 非module入力に限り64KiB chunkのstreaming hashへ分離。1file256MiB、合計512MiB | 小さい合成fixtureで上限、link、変更、hash不一致を拒否。新しい実行プランでの全実入力検証は後続 |
| 復帰後に詳細resource/64armを小さな制御応答だけで回収できない | 別の有限な読み取り回収処理を準備。固定inventory、no-follow、前後stat/hash、partial保存 | 別の90秒枠を設計中。実OwnedSSHとの接続と全chainレビューは未完了。回収完了を品質・独立復帰検証の代用にしない |

mainに入った品質検証の変更も比較用runtimeへ取り込んだ。
GCCの最適化下で`-ftrapv`が加算probeを止めても減算を見逃す場合があるため、両probeを必須とする。
graderの新SHA-256は`340f0afb6abf0e31736f33ec9538c7d8c71071fd7db4e14d11a00a37a400d2d8`。
catalogは`277abb01f995890be289b2c3d2e679f8a3283a12040b54218991fc005c19c268`のまま。
新graderでの実モデル出力の評価はまだ行っておらず、過去の品質receiptを新runへ転用しない。

## 検証の範囲

変更後のhandoff/release/supervisor/launcherについて独立に95件の隔離テストが通過した。
GUI生成器は9件の合成テストに加え、上記の実PS5境界確認を行った。
CI・合成テスト・無害なnative引数確認は、実測比較、品質の独立採点、長時間の安定性、復帰実証を置き換えない。
隣接するGUI archiveはソースだけで、所有者の実plan・鍵・接続先・承認・raw結果を含まない。

## 次の判断に必要なもの

比較候補はprefill 256/512/1024、2課題、64回の起動・primer・coding taskを使う未承認案。
作業5400秒、復帰600秒の予算を持つ。親監視6455秒と別の回収90秒は各起点を明示して扱う。
これらは実測停止時間でも、以前の6分診断承認の延長でもない。

全sourceとplanのhash連鎖、既定preview、隔離stage/readback、結果回収接続の検証を終え、
具体的な新scopeを提示してから本番一時停止の承認を得る。
その後も独立品質評価、比較の採否、再現キット、適用・復帰、OpenCode実作業の完了条件が残る。

今回の知見は、異なるshellをまたぐ引数転送、認証後の自動処理、監視期限の起点、
大きな既存バイナリの固定、回収と評価の分離に応用できる。
個別のsource pin・Windows/WSL経路・gate寿命はこの環境に固有であり、そのまま汎用化しない。
