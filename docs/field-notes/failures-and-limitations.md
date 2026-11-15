# 失敗と制限

## F-001: mock成功は実測・適用の証明ではない

既存MVPは合成値を厳密検証する契約だった。これに実測を混ぜると意味が変わるため、実測plan/run/quality/kitを別契約にした。CI・単体試験・manifest検証だけで初号機完了にしない。

## F-002: socketのidle timeoutだけでは総時間を制限できない

SSEの改行を送らず少量ずつ送信する試験で、最初の実装は制限時間を超過した。HTTP接続がclose扱いになる場合、connection側のsocket参照だけでは読取を中断できなかった。

要求直後のsocketを保持し、独立タイマーでshutdownする方式へ修正。意図的なslow-trickle、欠落DONE、不正JSON、応答上限、401、tool deltaの分割を検証する。実EVO経路での生成時間やキャンセル反映はまだ未測定。クライアントの接続終了がエンジンの生成停止を保証するとは扱わない。

## F-003: stdout採点は悪意ある候補に偽装され得る

実装に関与していないレビュー担当が、誤ったC++関数にstatic constructorを追加し、期待する観測行を出力して早期終了する候補を作った。初期graderはharnessのファイルhashが不変でも合格した。

この反例により、実行出力の一致だけを独立品質合格と呼べないと判明した。ソースに結び付いた独立確認と実行観測を分離し、未確認候補は採用不可にする。小課題の候補はソース変更、I/O、初期化、終了・プロセス操作、テスト改変を独立に確認する。ハッシュは内容の同一性を示すが、レビューの正しさや採点器への攻撃不在を数学的に保証しない。

## F-004: コンパイラ非互換をモデル誤答と混ぜない

既存C# starterはC# 6の式形式メソッドを含む。旧Windows FrameworkのC# 5コンパイラを無条件に使うと、修正内容と無関係にコンパイルが失敗し得る。所有者環境に既存の.NET SDKが見つかったため、Roslynと参照assemblyを直接指定し、restoreやダウンロードなしでコンパイルする経路を追加した。

コンパイラ、参照assembly、runtimeのhashと固定runtimeconfigを記録する。共有OSライブラリの完全な固定は別の確認が必要。

隔離検証では、通常環境で通る.NETコンパイラが`SIGXFSZ`で終了した。既存Pythonの`ptrace`による限定診断で、CoreCLRが`memfd_create`後に2 TiBの疎な領域を`ftruncate`しようとすることを確認した。これはモデルや生成物の実サイズではない。ファイル上限を拡大せず、.NET子プロセスに限ってPythonのSIGXFSZ無視を維持し、上限超過をEFBIGとしてランタイムへ返すことで代替処理が成立した。GC heap上限512 MiB、仮想アドレス上限8 GiB、元のファイル上限64 MiB、読み取り専用workspace、容量制限付きtmpfsでC#のコンパイル・16観測を確認。ソースレビューがない結果は、この成功後も品質採用不可のままである。

## F-005: 本番の同時ロードとSSD観測

現在のUMA使用状況では、本番モデルを残した候補の同時ロードを前提にできない。停止・切替には所有者の具体的な確認と、今回の復帰検証が必要。既存SSD観測プロセスが存在するので、測定時間帯を記録し、通常利用の24時間観測と負荷試験を混同しない。観測プロセスは変更・停止しない。

追加の読み取り確認では、既存観測は60秒ごとにprocess情報を読み、1時間ごとに書込み集計を保存していた。試行ごとの読込み・書込み速度には不足するため、既存観測を維持したまま、block stat・I/O PSI・CPU累積counterを1秒ごとに読む有限の補助計測を用意した。実機で2秒の接続・形式確認を実施し、2サンプルと終了記録、所有SSHジョブの回収を確認した。この区間のblock statの読込み・書込み量と完了I/O件数の差分は0であり、モデル推論の性能やボトルネックの証拠ではない。

本測定では実際の時刻と欠測区間を確認する。ホスト全体のcounterは他の仕事を含み、待ち時間counterは並行I/Oで壁時計以上に増え得る。これらだけで飽和や原因を断定しない。512-byte sectorと各counterの意味は[Linux block statistics](https://docs.kernel.org/block/stat.html)、待ち状態は[PSI](https://docs.kernel.org/accounting/psi.html)に従う。

## F-006: 公開自己テストと独立採点を分ける

`python -m aotg.field_selftest --source /task/intervals.cpp --public-test /task/PublicTests.cpp --compiler /usr/bin/g++ --allow-execute` は、明示したソースと公開テストだけを読み取り専用の隔離workspaceへコピーし、一時領域でコンパイル・実行する。C++の公開テストは対象ソースをincludeする。C#は既存.NET 8のRoslyn・参照assembly・runtimeを直接指定し、restoreや取得を行わない。ユーザーの`.dotnet`全体を公開せず、必要なツールの部分だけを読み取り専用で渡す。

実機WSLの公開C++／C# starterはいずれも不合格、既知の正例はいずれも合格し、元ファイルのhashは不変だった。隔離確認、書込拒否、timeout、出力上限も検証した。これは公開テストの実行経路の確認であり、推論やOpenCodeによる修正成功の証拠ではない。結果の`independent`と`quality_accepted`は常にfalseで、独立テストやソースレビューを代替しない。

## F-007: 親プロセスの終了だけでは試行の終了を証明できない

独立レビューで、親から離れた子が親の終了後も動き、遅れてファイルを作る反例を再現した。固定したOpenCode版もLinuxではbashをdetachedで起動するため、架空の条件だけの問題ではない。K8のクライアントには専用PID namespace、EVOの候補には所有するsystemd cgroupの残存確認を使い、残存が不明なら次の候補へ進まない。

Windows SSHはWSLのPID namespaceだけでは回収を証明できない。既存SSHを停止状態で起動し、kill-on-close付きWindows Job Objectへ割り当ててから再開する私用transportを検証した。実Windowsの親・子・孫による正常終了、timeout、WSL側の強制終了試験で残存と遅延markerがないことを確認。実SSHによる既存APIのhealth GETも成功した。これは接続と終了処理の実証であり、生成性能や実機サービス復帰の実証ではない。各接続のJobEmpty結果を確認してから測定記録を確定する。

## F-008: 隔離起動には既存Python依存関係の明示が必要

所有者実機では、制御用のシステムPythonとStrata用Pythonの版が異なる。さらにStrata用Pythonを`-I -S`で起動し、既存の制御ソースだけを指定して読み取り専用import検査を行うと、既存のJinja2が見つからず停止した。実機workerのファイル照合と復帰コマンドのdry-runが通っても、実際のimport closureが成立するとは限らない。

不足を新規ダウンロードで埋めず、既存依存packageの所在と内容を個別に確認し、ハッシュ固定した範囲だけを利用する。`.pth`や暗黙のユーザー設定の読込と混同しない。現時点のこの失敗はサービスを止める前の検出であり、隔離サーバーの実起動成功は未確認。

## F-009: CI環境の隔離機能と実機の隔離機能を区別する

K8 WSLではuser/mount/PID namespaceを利用できたが、Linux CIのポリシーでは同じ操作が拒否された。実装の要件を緩めず、テストで同じnamespace起動経路を事前に確認し、明示的な権限拒否の場合だけ成功系の実行試験をskipする。未知のprotocol不具合は失敗のままにし、隔離不能時の拒否試験は維持する。CIのgreenを実機隔離の証拠として代用しない。

## F-010: 単独で動く隔離環境も入れ子では起動できないことがある

実測した事実：K8 WSLで、クライアント側の外側user namespaceを`--map-root-user`で作成し、capabilityをすべて落とした後に公開自己テストの内側user namespaceを起動すると、`uid_map`への書込みが`EPERM`で失敗した。それぞれの隔離環境が単独で起動できることだけでは、この組合せの動作を証明できなかった。観測環境はWSL kernel `6.6.87.2-microsoft-standard-WSL2`、util-linux `2.39.3`。モデルやGPU推論を使わずに再現した。

原因についての推論：Linux 5.12以降、親namespaceのUID 0を含むmappingには、書込み元またはnamespace作成時の`CAP_SETFCAP`について追加条件がある。今回の外側UID 0とcapability除去の組合せは、この条件による拒否と整合する。カーネル内部の分岐を直接traceした結果ではない。[Linux user_namespaces(7) のUID mapping条件](https://www.man7.org/linux/man-pages/man7/user_namespaces.7.html)

外側を`--map-current-user --keep-caps`へ変更し、元のUID/GIDを維持した。保持するcapabilityは直後の`setpriv`までとし、クライアント起動前の専用pipeによる確認で`CapInh`、`CapPrm`、`CapEff`、`CapBnd`、`CapAmb`がすべて0、`NoNewPrivs=1`であることを要求する。

修正後は実際のクライアント起動関数から`./verify.sh`を実行し、その内側で既存g++ `13.3.0`と.NET SDK `8.0.424`／runtime `8.0.30`によるコンパイル・実行を検証した。C++／C#の両方で、不正な初期実装は`test-failed`、既知の正しい実装は`pass`になり、公開自己テストと入力ファイルは変更されなかった。再現コマンドは`python3 -m unittest tests.test_field_client.NestedNativePublicSelftestTests -v`。この結果は隔離層の組合せと公開自己テストの実証であり、モデルの品質・推論性能・実機適用完了は別の検証を要する。ほかの環境でも、単独の機能確認に加え、実際に入れ子となる起動経路を検証することが有効と考えられる。

## F-011: 短時間のTTFTテストは時計分解能を無視できない

観測した事実：PR #15のマージ後[CI 43707077964](https://github.com/uobnnisiuk/AOTG/actions/runs/43707077964)で、Windows／Python 3.11.9の1テストが失敗した。各SSE eventの前に10 ms待つfixtureに対し、TTFTが15 msより大きいという期待値があり、実際の値は`0.014999999999986358`だった。他の3構成は成功した。これは合成SSEのテストで、EVOの推論結果ではない。

原因についての推論：その版のWindows実装は`GetTickCount64()`を使うため、時計の刻みと浮動小数点境界による結果と整合する。失敗したCIホストで時計分解能を直接測定したわけではない。[CPython 3.11.9の実装](https://github.com/python/cpython/blob/v3.11.9/Python/pytime.c#L968-L1005)

[PR #16](https://github.com/uobnnisiuk/AOTG/pull/16)で、実socketによるSSE・内容・usageの検査を残し、時刻の開始条件は決定論的な時計で別に検証した。roleだけのdeltaと空deltaを無視し、最初のcontentまたはtool deltaでTTFTが始まり、後続deltaで上書きされないことを検査する。再現は`python -m unittest discover -s tests -p test_field_bench.py -v`。11テストと独立レビューが成功し、マージ後[CI 43707952148](https://github.com/uobnnisiuk/AOTG/actions/runs/43707952148)も全4構成で成功した。測定実装・固定済み実機入力は変更していない。

初号機のK8 WSL Python 3.12.3は`clock_gettime(CLOCK_MONOTONIC)`、申告分解能1 nsだったが、申告値を実測精度の証明としない。将来の他OS対応では時計の実装・申告分解能を測定条件に記録し、短い差の扱いを再検討する。汎用版の時計変更や精度改善は未実施。
