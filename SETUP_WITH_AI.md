# 接続専用入口の導入・移行

既存のMCP設定とトークンは変更せず利用する。トークンをAIへの会話、Git、URL、ログへ記録しない。

## 既存の利用者

1. 現在の `web-design-pro` Skillの実体パスを確認する。既存の接続設定・トークン・Figma .runtimeを削除しない。
2. `scripts/private-client.py`を、このSkillフォルダの外にある作業領域へ取得する。
3. MCPの契約情報にあるSHA-256と取得したインストーラーを照合する。
4. `python3 <取得したprivate-client.py> --destination <現在のweb-design-pro> --migrate`を実行する。別のCodex設定を使う場合だけ`--config <使用中のconfig.toml>`を加える。
5. 更新後の同じ場所のSKILL.mdを読み直す。`scripts/update-client.sh`を再実行しcurrentを確認する。

既存のローカル変更を検出したら上書きせず、バックアップして差分を確認する。GitHubの旧originを変更したり、git resetで変更を削除したりしない。

## 新規の利用者

Python 3.11以降を使用する。このリポジトリを `~/.codex/skills/web-design-pro` にcloneする。
トークンが環境に設定済みなら、上のインストーラーを`--migrate`で実行する。
未設定の場合だけ、利用者自身の端末で`--prompt-token`を追加して実行し、非表示の入力欄へ本人に入力してもらう。トークンはインストーラーのメモリ内で認証にだけ使う。
取得後はクライアント内のSETUP_WITH_AI.mdに従い、MCP設定とOSの資格情報ストアを整える。既存設定があれば保持する。
