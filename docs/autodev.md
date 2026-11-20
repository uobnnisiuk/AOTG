# AOTG Local AutoDev

この変更は、承認済みソフトウェア課題の候補選定からDraft PRの確認までを、AOTG専用の状態と実行境界で扱う。承認や作業範囲は [AOTG-AUTODEV-V1](https://github.com/uobnnisiuk/AOTG/issues/2) と [基盤の課題](https://github.com/uobnnisiuk/AOTG/issues/3) に従う。

## 実行順序

1. GitHubのmain、全オープンPRと参照、Linearの課題と依存完了を読み取る。Draftを含むオープンPRがあれば停止する。承認元は運用者が管理し、承認には対象の課題、課題スコープの版、依存課題、変更許可パスを固定する。課題本文やラベルが承認元になることはない。ハッシュは承認記録の照合に使う。
2. 既存予約を検査し、独立したローカル台帳で予約を確定してから、専用ブランチを一度だけ作成し、読み戻す。開始はJST日次2件まで、3時間以上の間隔、同時1件とする。失敗・期限切れ・結果不明でも予約を消費し、異常な台帳や中断した予約は調査まで保留する。
3. 固定したmainを専用checkoutから別の作業コピーに取り込み、ベースと作業ツリーを検査する。モデル実行と実行環境の制御には40分の上限を設ける。プロセスグループの停止に加え、子プロセスが残らない隔離とファイルアクセスの制限を配備前に検証する。許可パスと作業ツリー全体の差分を照合し、保護対象の変更を拒否する。Workerは公開用コミットの証拠を返す。課題本文をシェル引数に変換する経路は設けない。
4. 公開前に承認・main・オープンPR・予約ブランチを再確認する。差分とローカル検査の証拠が揃えばDraft PRを作成し、実際のbase、head、Draft状態とブランチを照合する。結果欄には課題ID、時刻、状態、理由コード、PR番号、base/head SHAだけを返す。結果の読み戻しや全オープンPRの再確認に失敗した場合は結果不明として止まる。GitHubの他の書き手とは共通のトランザクションを持たないため、実運用では外部からのPR作成と時期を調整する。レビューとマージは次の独立工程が担当する。認証付きの書き込み先との接続と、配布前に内容を検査する境界は実運用の前提とする。

### ADV-1：候補の確定不合格と結果不明の区別

モデル実行後に許可されたファイル数・変更パスの不一致が確認できた場合、または固定されたオフライン独立検証が完全な採点結果を照合して明示的に不合格を出した場合は、候補を**不採用**とする。 採点コマンドが契約上の終了コード `0` または `2` で終了し、標準出力を上限内で最後まで取得できた場合は、終了コードの不一致と不正なJSONも確定不合格とする。検証器は実行ごとに異なる識別値を受け取り、照合を終えたときだけ、その値と判定を専用の一時証拠に書く。起動元は証拠ファイルと専用終了コードの一致を確認する。候補プロセスには識別値を渡さない。

固定コード `blocked/candidate-rejected` を結果欄へ記録し、その内容を読み戻せた場合だけ台帳に `failure` を確定する。同じIssueの予約は再利用しないが、以降の別Issueは日時・承認・PR制約を満たせば進められる。不合格の候補をGitHubに公開しない。

モデル生成自体の失敗、サンドボックスや検証器の起動異常、採点コマンドのシグナル終了・契約外の終了コード・応答期限切れ・出力上限超過、候補が追加したテストも読み込むテストスイートの失敗、終了と証拠の不一致や欠落、結果保存やGitHub操作の不確実性は `unknown` として保留する。プロセス全体の時間切れは従来どおり `timeout` として区別する。結果欄へ例外の本文・モデル出力・機密ログを書かない。

### ADV-18：観測の値を無視する採点器の拒否

初回パイロットの独立契約は、元の観測の一致、欠測、timeout、型・JSONの不正、順序の不一致に加え、両ケースの観測値を一つずつ変えた入力を検査する。各 `result` は真偽値のまま反転し、引数の整数と文字列、C#の操作対象・グループ名も同じ型の別の値にする。配列の長さと順序、キーは維持し、先頭以外を含むすべての既存位置で `assertion_mismatch` と終了コード0を要求する。元のcatalogは変更しない。

この契約とfixtureは生成用checkoutにも含まれる**公開の固定検査**であり、秘匿された未見テストではない。合格はこの有限な入力集合での契約適合を示すだけで、未知入力への正しさや過適合の不存在は証明しない。検証器の受領証の保護と、検査内容の網羅性は別の性質である。独立した差分レビューは引き続き必要で、この修正は初回モデル試行の予約・利用枠・実行承認を更新しない。

## Shadow 検証

```sh
python -m unittest discover -s tests -p 'test_autodev_*.py' -v
python -m aotg.autodev shadow
```

最初のコマンドでは承認と公開先を模擬し、実際の一時Gitリポジトリで隔離した作業コピーと差分を検査する。経路の失敗、結果の再取得、台帳の競合と日付境界も試験する。結果はshadowの検証として扱う。2番目のコマンドは公開GitHubのmain、初回PR、オープンPRとブランチを読み、候補選定の前提を確認する。

`Coordinator.run_once` は既定で書き込みなし。実行モードで必要な `GitHubPort`、`WorkerPort`、`ResultSlot` は信頼できるローカル配備が用意する。レポートと台帳はAOTG専用とし、既存の他プロジェクトのスケジュール、ロック、承認、データ、予算から分離する。[Footprintの運用例](https://github.com/uobnnisiuk/footprint-sim/blob/main/docs/autodev-daily.md) · [時間ごとの確認](https://github.com/uobnnisiuk/footprint-sim/blob/main/docs/autodev-hourly.md) · [候補選定](https://github.com/uobnnisiuk/footprint-sim/blob/main/docs/autodev-queue.md)

## 承認キューのシャドウ接続

引数なしの `python -m aotg.autodev shadow` は公開GitHubを読み取る。運用者が管理する承認ファイルを使えば、モデル起動・予約・書き込みを伴わずに選定結果を確認できる。

```sh
python -m aotg.autodev shadow --approvals "$APPROVAL_FILE" \
  --github-cli "$VERIFIED_GH" --linear-authorization "$LINEAR_AUTHORIZATION_FILE" \
  --ledger "$AOTG_LEDGER"
```

- 承認ファイルとLinear認証ファイルは、WSLのcheckout外にある運用者専用ディレクトリに置く。親ディレクトリは `0700`、ファイルは `0600`。認証ファイルには別途承認されたLinear接続の認証値を1行だけ置く。認証値・承認履歴・結果ログはGit管理外。
- 承認ファイルの形式は `{"version":1,"policy":"AOTG-AUTODEV-V1","repo":"uobnnisiuk/AOTG","scopes":[]}`。空なら実行候補を選ばない。各スコープに `issue`、`github_issue`、`revision`、`allowed_paths`、`dependencies`、`approval_sha` を指定する。最新版と承認対象を照合するため、`LinearIntake.snapshot` の版と依存関係を確認し、許可内容を `scope_digest` で固定する。承認はハッシュを計算したことでは成立しない。承認ファイルへの登録は、所有者が対象と変更範囲を明示した後に行う。
- GitHub CLIは信頼できる既存の実行ファイルを絶対パスで指定する。GitHub Issue番号と作成者、Linearのプロジェクト・依存・版を別々に照合する。空の承認ファイルから認証先や候補を推定しない。
- 結果送信には、運用者が指定したGitHub #3とLinear UOB-58の固定コメントを使う。初期本文は `` `AOTG-AUTODEV-V1/result` ``。コメントのID・所属課題・作成者を照合し、構造化済みの単一結果だけを更新する。2サービスの更新は一括確定できないため、途中で失敗した場合は保留記録を残し、再送前に両方の実状態を確認する。
- Draft作成用のGitHubアダプターは、先に検証済みコミットが専用ブランチに置かれ、固定されたベースと変更パスに一致することを要求する。検証済みの候補を渡す初回パイロットの接続は下記を参照。シャドウCLIに本番実行モードは追加していない。

## 初回パイロット

初回候補は [GitHub #7](https://github.com/uobnnisiuk/AOTG/issues/7) のオフライン採点に固定する。既存の合成C++／C# fixtureを使う。許可された3つの変更パス、現在のLinear依存関係、実行したいmain、承認済みスコープのダイジェストを照合する。モデルに渡す指示は管理された固定文とし、Linearの本文は版の照合だけに使う。

- `pilot_installation.run_configured_pilot` はAOTG専用の信頼できる起動元から1回呼び出す。既存の `shadow` コマンドと無効タスクには実モデル起動を追加しない。
- 専用領域の `config/first-pilot-release.json` に、別途承認された1回限りのChatGPTプラン試行を記録する。固定フィールドは `version`（1）、`policy`、`approved_by`、`issue`、`github_issue`、`base`、`scope_digest`、`issued_at`、`expires_at`、`authorization`（`one-chatgpt-plan-pilot-no-extra-charge`）。日時はUTC秒精度で `+00:00` を付ける。許可時間外、変更されたmain、別スコープ、認証や安全条件の不足、オープンPR、既出の予約で停止する。
- 起動元が、隔離動作を検証したCodexのバイナリ・専用認証・サービス通信・外部ツール制限を確認する。モデルに接続するクライアントと、モデルが実行するコマンドの通信制限は別に検証する。生成とテストは別の作業コピーで実行し、外部から与えた合成fixtureの採点契約も確認する。テスト後に作業差分を取り直す。
- 検証済みパッチを公開用の別checkoutに再構築し、親コミットと許可済みパスを照合する。予約ブランチが固定ベースを指すことを確認し、通常のHTTPS pushで更新してからDraft PRを作る。両方の結果欄を読み戻せない場合は予約を消費したまま停止する。
- 初回試行は専用のWSLユーザーサービスで1回だけ実行する。サービスの起動、事前確認、候補生成、公開と結果確認、停止までの合計が40分以内になるよう余裕を取る。開始前と書き込み前にWindowsのタスク状態を確認し、Footprintの実行中や試行時間と重なる予定、確認不能を検出した場合は停止する。タイムアウトや応答不明時は台帳・予約ブランチ・結果欄を照合してから判断する。
- 起動元は配備済みの完全なmain SHAを指定し、作業コピーの変更や有効なスケジューラがないことを確認する。初回モデル試行には、別に承認された `first-pilot-release.json`、承認済みスコープ、同じSHA・スコープ・実行UID・有効期限を対象とした `pilot-deployment.json`、AOTG専用のGitHub／Linear認証が必要。配備の記録には、専用のChatGPTログイン、追加課金のないプラン利用、モデルクライアントの通信先の制限、管理対象の外部ツール無効化について独立に確認した結果を残す。記録と認証はcheckout外の非公開領域に置く。
- 試行の証拠を確認してから定期実行の承認を求める。自動マージは [UOB-59](https://linear.app/uobnnisiuk/issue/UOB-59) の独立レビュー・承認・CIの条件を別途検証する。

モデルも外部サービス認証も使わず、実際の起動元とWindowsの状態確認を試すには、レビュー済みの `pilot_supervisor.py` をcheckout外の運用者専用領域に固定し、`--probe` で呼び出す。起動元はプロジェクトコードを読み込む前にcheckoutのSHAと未追跡・除外ファイルを含む状態を照合する。完了は起動と状態確認ができたことを示す。

```sh
python3 -I -B "$AOTG_PINNED_SUPERVISOR" --probe "$AOTG_CHECKOUT" "$MAIN_SHA"
```

## 専用認証の準備

- GitHubは所有者のfine-grained PATで、AOTGリポジトリだけを選ぶ。権限は `Contents: Read and write`、`Pull requests: Read and write`、`Issues: Read` と、GitHubが付与する `Metadata: Read`。Linearは結果欄の投稿者が、UOBチームだけにアクセスできる個人APIキーに `Read` と `Write` を設定する。
- レビュー済みの `auth_import.py` を専用領域で固定し、ローカル端末の非表示入力から新規認証値を登録する。専用ファイルの権限は `0600` とし、新規ファイルの作成だけを許可する。起動元で承認済みmainと作業ツリーを照合し、専用領域に固定した `auth_verify` を呼び出す。結果は本人性、対象、固定結果欄の読み取りに限る。書き込み可否と、発行画面で設定した権限範囲は別に確認する。
- Codexは既存ChatGPTプランで本人がサインインする。専用のChatGPT認証キャッシュは `config/codex` に保存し、モデルクライアントだけが `CODEX_HOME` として使う。`aotg.autodev.chatgpt_signin` の `probe` と `status` はモデルを起動せず、`device-login` はローカル端末での本人認証時にだけ使う。接続確認で認証が成立しても、初回モデル試行用の承認と通信制限の検証は残る。

## K8への配備と復帰

- 配備前に、K8のWindowsとWSLの実行主体、専用checkout、GitHub／Linearへの権限、既存のCodexログイン状態を確認する。Codexを起動するアカウントには登録済みプランの利用だけを許可し、追加購入や従量課金の利用は別途承認する。
- 配備先にAOTG専用の作業、状態、結果のディレクトリを用意する。WSLでは台帳ディレクトリを所有者のみアクセスできる `0700`、レコードを `0600` にし、Windows側のアクセス制御も別途照合する。
- タスク名は `AOTG Local AutoDev`。初回は登録に必要な承認を得て無効状態で準備する。同名タスクがあれば停止して状態を照合する。無効のshadow用タスク定義は `aotg.autodev.task_definition.disabled_task_xml` で生成できる。配備時は毎時最大1回の確認、重複起動と欠落回の追いかけを禁止し、40分で実行を打ち切る設定を確認する。Workや他の負荷と安全に共存できる証拠が欠けた場合は候補を実行しない。
- スケジュールを有効にする前に、破棄可能な専用環境でshadowを実施し、固定結果欄の読み戻しと重複拒否を確認する。既定では無効を維持する。実Issueの初回モデル実行は承認された試行枠を使い、GitHub側のDraft PRと照合できた時に実動作として記録する。
- 復帰時はAOTGタスクだけを無効にし、実行中の作業が収束したことを確認する。登録前の状態へ戻す場合はAOTGタスクだけを撤去し、予約済みの台帳・ブランチ・結果は調査と再開判定のため保持する。

### 初回試行の通信と利用枠

モデルを呼び出すCodex本体の通信は、プロセス単位のLinuxネットワーク分離とTLS中継で制限する。中継は `chatgpt.com:443` へのCONNECTと一致するTLSサーバー名を確認してから接続する。許可外の要求、中継の障害、制限の初期化失敗は実行結果を不明として停止する。Codexが起動するコマンドは、既存の権限プロファイルでさらに分離し、認証領域と中継口へのアクセスを拒否する。

配備記録の `bwrap` と `bwrap_sha256` は、AOTG専用領域に置いたホスト標準のBubblewrap実行ファイルとそのSHA-256を指定する。公式の配布情報で確認したファイルを使い、専用ディレクトリにはその実行ファイルだけを置く。コードや候補の作業領域から指定先を変更できないようにする。

利用枠は専用ChatGPT認証でCodex App Serverの `account/read`（`refreshToken: false`）と `account/rateLimits/read` を使って読み取る。利用枠の残量は照会時点の値として扱う。利用枠内だけで開始するには、購入済みクレジットが使われないことと自動購入が無効であることを同じアカウントの利用状況で確認する。クレジットの購入、上限のリセット操作、従量課金APIへの切替は行わない。[Codex App Server](https://learn.chatgpt.com/docs/app-server#authentication-and-accounts) · [利用状況](https://chatgpt.com/codex/settings/usage) · [自動購入の仕様](https://help.openai.com/en/articles/12642688-using-credits-for-flexible-usage-in-chatgpt-personal-plans)
