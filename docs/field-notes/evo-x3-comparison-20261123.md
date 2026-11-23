# EVO-X3初号機: 2026-11-23 比較中断と独立復帰確認

## 結果

所有者が承認した新しい64試行の比較を1回実行した。最初の基準構成（prefill512）の読み込み中に、
新しいswapoutを検出した安全監視が停止した。開始したarmは1、完了したarmとコーディング課題は0/64、
代替候補の実行は0件である。性能改善率、同品質の速度比較、採用判断は算出できない。

認証1回からdetached監視、開始信号、停止判定、自動復帰、部分結果の回収まで追加のチャット返答なしで進んだ。
その後の独立した読み取りで、元の本番unit・19保護ファイル・推論プロセスの基準一致とAPIの待機状態を確認した。
これは初号機Goalの完了ではない。同じ承認・gate・試行は消費済みで、再実行していない。

## 比較条件とソフトウェア

対象は所有者の既存EVO-X3＋K8 Plus系統。今回の準備時に本番19ファイルとnative引数・実行ファイルstatを基準照合した。
モデル、量子化、GPU配置、OS、ドライバは変更せず、R9700の追加候補も実行しなかった。
計画はprefill256/512/1024、C++半開区間課題とC#バッチ登録課題、
各比較にABBA/BAAB/BAAB/ABBAの4ブロック、計64回の起動・primer・課題実行で固定した。
今回は最初の512構成だけがready前に停止した。

準備時のmainは `3a5d85c08c230c6c123da87abc61d21f21dcd2e0`。
worker SHA-256は `692904c3d1c394fe617a2a16a76284925c2823f2cc52a3e26d3376b7119538f9`、
graderは `340f0afb6abf0e31736f33ec9538c7d8c71071fd7db4e14d11a00a37a400d2d8`、
catalogは `277abb01f995890be289b2c3d2e679f8a3283a12040b54218991fc005c19c268`。
graderはこのrunのモデル出力を採点していない。

作業5400秒、復帰600秒、親監視・回収を合わせた構成予算6590秒で実行した。
実際のworker時間は5.852980秒、親の比較監視は59.097988秒、後続回収制御は3.547464秒。
これらは同一の起点から測った値でも、本番の実測停止時間でもない。

## 観測の時系列

下表は日本時間。隣接JSONの原本時刻はUTCである。

| 時刻（2026-11-23 JST） | 保存された事実 |
|---|---|
| 15:52:52 | detached supervisor起動 |
| 15:53:04 | worker開始、新しいpswpout起点115を取得 |
| 15:53:10 | pswpout158のsampleを保存後、guardが拒否 |
| 15:53:38 | ownerがworker-failed-restored、unit復帰済みと報告 |
| 15:53:56 | 部分結果回収終了 |
| 15:55:29 | 独立SSH読み取りで保護19件・native基準・本番unit成功を確認 |
| 16:01:15 | 既存APIへGET /slots、HTTP200・1 idle slot |
| 16:08:06 | 試行用4unitのinactive状態と限定したサンプラ不在を読み取り確認 |

本番unitはoneshotでactive/exited/success、MainPID=0である。別に確認したnativeプロセスが基準のargvとexe statへ一致した。
MainPID=0だけをエンジン不在と解釈しない。API確認は一時点のGETのみで、新たな推論やC++/C#生成を行った証拠ではない。

## 停止理由: 事実、推測、未検証

新しい起点115に対し、sequence0〜27は115のまま通過した。
sequence28では158（+43）となり、同sequenceのguard-resultが
`New swapout or counter reset`を記録した。今回は実際の増加が保存されており、
古い起点の転用、欠測、カウンター低下で停止した事例ではない。

SwapUsedの観測値は450,560から626,688 bytesへ増加した（差176,128 bytes）。
メモリ、VRAM、温度など他の監視値はその判定時の閾値内だった。
nativeプロセスを観測できた22 sampleのVmSwapはすべて0である。
したがって、そのnativeプロセス自身がswapされたとは言えない。

engine logの末尾はモデル読み込みとexpert-cacheのprofile fillに関する表示だった。
これは時刻上の一致であり、GPUキャッシュ確保が今回のswapoutを起こしたと示す証拠ではない。
どのプロセス・メモリ領域が対象だったか、cgroup単位のswap変化、memory PSIやreclaimの遷移は未収録である。
ログ上のcache容量はプログラムの表示値として分け、実測量として扱わない。

サーバ末尾のKeyboardInterruptは、guard停止後の所有プロセス終了処理と整合する。
これだけを独立したエンジンクラッシュの根因にはしない。
kernelの固定エラーパターン走査はclearだったが、全kernel logの確認でも、reclaimが無かった証明でもない。

## 回収と終了の確認範囲

collectorは復帰報告に結合した固定517 pathを1回で全件確認し、存在した10ファイル（96,283 bytes）を回収した。
残る507件はready/doneや開始されなかったarmの未生成ファイルで、FileNotFoundErrorとして保存された。
全wire frameと各raw/partial hashを独立照合した。今回のincompleteは通信途切れや期限超過ではなく、
計画した全結果が存在しないことを表す。これを完全な比較結果へ昇格させない。

補助I/Oは51 sampleを保存し、workerの開始から停止を含む時刻帯を覆う。
早期停止後にcancelしたため最終frameが無く、固定期限までの完全収録ではない。
host/device合計の観測であり、swapの原因プロセスやSSD飽和を特定する情報ではない。

12件の制御・client・release・collectionのWindows Job記録はJobEmptyを確認した。
別のI/O JobもJobEmptyだったが、cancelで最終frameが無く、このreceipt単独からremote終了を認定しない。
K8の記録済みsupervisor/watcher/release/client/collectorとI/O wrapperのPIDは読み取り時に不在だった。

EVOの認証・worker・復帰service/timerの4unitはinactive/not-found/dead。
保存されたowner PIDは不在、uid1000に限定した有界proc走査も完全一致する試行ID・結合hashのサンプラを見つけなかった。
走査は一時点の限定観測であり、未知の全子孫プロセスの終了証明ではない。対象へのsignalや再実行は行っていない。

clientは `Owned remote state operation failed` を記録し、唯一の当該SSH Jobはexit1だった。
workerの終端状態検知と整合するが、そのremote stderrは保存されていないため、直接の例外源は未証明である。
将来は型付き終端状態と上限付き診断を保存する余地がある。

## 次の改善と再現方法

swapoutゼロ増加を含む安全条件は緩めず、起動後に起点を取り直す変更もしない。
次の診断に向け、限定したcgroup memory/swap・memory PSI・reclaim countersを保存する補助コードを隔離環境で準備する。
通常のguard判断と拒否時cleanupを先行させ、補助読取の欠測を0や成功へ変換しない。
これは原因情報の不足を減らす候補であり、今回のswapout原因の解決や次回成功を証明するものではない。
補助行が増えるため、実使用前に採取頻度・総行数・総bytesと既存collector上限を結合して再検証する必要がある。
今回の実行source・plan・collector上限へは適用しておらず、helper候補の合成試験を実機修正の成功と扱わない。

公開JSONには再集計用の値と原本hashを保存した。非公開rawは上書きせず、各取得のjob/plan/payloadを結合している。
再解析ではworker summary、guard前観測と判定の同sequence、accepted resourceとの差、
client summary、collector inventory、独立復帰baseline/APIを別々に照合する。
将来の実機再現には新しい固定scopeと承認が必要であり、この消費済み試行の再利用はしない。

この環境固有のカーネル・メモリ配置・常駐負荷と、汎用化できる「global counterと個別原因の分離」を区別する。
起動診断の単発成功は後日の同条件成功を保証しない。次回の診断情報を増やし、
比較・品質・再現キット・適用の未完了条件を埋める。今回の改善率は0%ではなく未判定である。
