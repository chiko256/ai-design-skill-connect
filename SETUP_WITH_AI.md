# 接続専用入口の導入・移行

既存のMCP設定とトークンは保持する。トークンをAIへの会話、コマンド本文、Git、URL、ログへ記録しない。

## 実行環境

Python 3.11以降を確認する。macOS/Linuxでは`python3`、WindowsのPowerShellでは`py -3`を使う。Windowsでpyがない場合は、確認したPython実体の絶対パスで実行する。空白を含むパスは引用符で囲む。PowerShellで引用した実行ファイルを起動する場合は`&`を付ける。Windowsでは.shを実行するための追加シェルは不要。
WindowsとWSLは別環境として扱い、Codexを動かす側のPython・設定・資格情報を使う。

## 既存の利用者

1. 現在の`web-design-pro` Skillの実体パスを確認する。既存の接続設定・トークン・Figma .runtimeを削除しない。
2. MCPの契約情報のinstallerUrlから`private-client.py`をSkillフォルダの外の作業領域へ取得し、installerSha256と照合する。
3. `python3 <取得したprivate-client.py> --destination <現在のweb-design-pro> --migrate`を実行する。Windowsでは先頭を`py -3`へ置き換える。別のCodex設定を使う場合だけ`--config <使用中のconfig.toml>`を加える。
4. 更新後の同じ場所のSKILL.mdを読み直す。認証設定が有効なら、同じインストーラーを再実行してcurrentを確認する。

既存のローカル変更を検出したら上書きせず、バックアップして差分を確認する。GitHubの旧origin変更やgit resetは行わない。

## 新規の利用者

1. このリポジトリを、Codexが使うSkillフォルダ内の`web-design-pro`へcloneする。標準はmacOS/Linuxが`~/.codex/skills/web-design-pro`、Windowsが`$HOME\.codex\skills\web-design-pro`。
2. すでに契約認証が利用できれば、その設定を使う。Windowsで未設定なら、利用者自身のPowerShellで`py -3 <このSkill>/scripts/private-client.py --setup-windows-auth`を実行し、非表示の入力欄へ本人に入力してもらう。Windows資格情報マネージャーへ保存され、再起動後も同じ利用者の接続で使える。
3. `python3 <このSkill>/scripts/private-client.py --destination <このSkill> --migrate`でクライアントを取得する。Windowsは`py -3`を使う。macOSで既存のtokenファイル・GUI環境・Keychainのいずれにも認証がなければ、利用者自身の端末で`--prompt-token`を加え、非表示の入力欄へ本人に入力してもらう。この一時入力は保存されない。
4. 取得後は同じ場所のSETUP_WITH_AI.mdを読み、**認証の永続設定→MCP設定→更新確認→接続確認**の順に進む。一時入力で取得した直後に、認証の保存前の更新確認を行わない。

## macOSの認証復旧

取得後のSETUP_WITH_AI.mdに従い、環境変数不足でHTTP MCPが起動できない場合はcodex-config.macos.example.tomlのstdio接続を使う。接続時に既存の認証情報を読み取り、旧tokenファイル・既存トークン・他MCPを保持する。Pythonとスクリプトの絶対パスを確認し、使用中のweb-design-pro接続ブロックだけをバックアップ後に変更する。設定例をそのまま実行しない。
