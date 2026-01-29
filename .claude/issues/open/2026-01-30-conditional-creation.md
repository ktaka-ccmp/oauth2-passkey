# Issue: Passkey Registration Promotion After Login

## ID: 2026-01-30-07

## Status: open

## Priority: medium

## Description

Implement passkey registration promotion after successful login to encourage users to add passkeys for faster future logins.

## Related Files

- `oauth2_passkey_axum/static/passkey.js` - Passkey registration
- `oauth2_passkey_axum/static/oauth2.js` - OAuth2 login flow
- `oauth2_passkey_axum/src/coordination/` - Server-side coordination
- `oauth2_passkey_axum/templates/` - Modal/prompt templates

## Notes

### Approach 1: Explicit Passkey Promotion (OAuth2 対応)

OAuth2 ログイン成功後に、パスキー登録を促すモーダル/プロンプトを表示する方式。

**実装概要**:

1. **Server**: ログイン成功レスポンスにパスキー登録可否フラグを追加
```rust
{
    "logged_in": true,
    "has_passkey": false,  // ユーザーがパスキーを持っているか
    "suggest_passkey": true  // 登録を促すか
}
```

2. **Client**: OAuth2 コールバック後にモーダル表示
```javascript
// OAuth2 ログイン成功後
if (response.logged_in && !response.has_passkey && response.suggest_passkey) {
    showPasskeyPrompt({
        title: "パスキーでログインを簡単に",
        message: "次回からワンタッチでログインできます",
        onAccept: async () => {
            // 通常の登録フロー
            const options = await fetch('/passkey/register/start').then(r => r.json());
            const credential = await navigator.credentials.create({ publicKey: options });
            await fetch('/passkey/register/finish', { method: 'POST', body: ... });
        },
        onDecline: () => {
            // "後で" - 一定期間表示しない
            localStorage.setItem('passkey_prompt_declined', Date.now());
        },
        onNever: () => {
            // "今後表示しない" - サーバーに保存
            fetch('/api/user/preferences', { method: 'POST', body: ... });
        }
    });
}
```

**メリット**:
- OAuth2 でも動作
- UI/UX を完全にカスタマイズ可能
- 「後で」「今後表示しない」などの選択肢

**実装タスク**:
- [ ] サーバー: ログインレスポンスにフラグ追加
- [ ] サーバー: ユーザー設定保存 API（表示しない設定）
- [ ] クライアント: プロンプト UI コンポーネント
- [ ] クライアント: localStorage での一時的なスキップ管理

---

### Approach 2: WebAuthn Conditional Creation (パスワード認証のみ)

ブラウザが自動でパスキー作成を処理する WebAuthn 標準機能。

**制限**: パスワード認証でのみ動作。OAuth2/identity federation では動作しない。

```javascript
navigator.credentials.create({
  publicKey: { ... },
  mediation: "conditional"
});
```

**Requirements**:
1. ユーザーがパスワードマネージャーにパスワードを保存している
2. そのパスワードが最近使用された
3. パスワードマネージャーがこの機能をサポート

**NOT supported with**:
- OAuth2 / Identity federation
- Magic links
- Phone verification

**本ライブラリでの適用性**:

| Auth Method | Conditional Creation | Explicit Promotion |
|-------------|---------------------|-------------------|
| Password login | Supported | Supported |
| OAuth2 login | **Not supported** | **Supported** |
| Passkey login | N/A | N/A |

→ 本ライブラリは OAuth2 + Passkey がメインのため、**Approach 1 を優先実装**

---

### 参考資料

- https://developer.chrome.com/docs/identity/webauthn-conditional-create
- https://github.com/w3c/webauthn/wiki/Explainer:-Conditional-Create
- https://blog.agektmr.com/ja/2025/12/passkey-keywords.html

## Resolution

