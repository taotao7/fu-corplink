import { useState } from "react";
import { api, ApiError } from "../api";
import { Card, Input } from "../ui/Card";
import { Button } from "../ui/Button";
import { Lock } from "lucide-react";

export function AdminGate({ onAuthed }: { onAuthed: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  async function submit() {
    setLoading(true);
    setErr("");
    try {
      await api.adminLogin(username, password);
      onAuthed();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "登录失败");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card>
      <div className="mb-5 flex items-center gap-3">
        <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-burnt/10 text-burnt">
          <Lock className="h-5 w-5" />
        </div>
        <div>
          <h2 className="text-base font-semibold text-ink">管理员登录</h2>
          <p className="text-sm text-ink-muted">控制面板已启用访问鉴权</p>
        </div>
      </div>
      <div className="space-y-4">
        <Input label="用户名" value={username} autoFocus onChange={(e) => setUsername(e.target.value)} />
        <Input
          label="密码"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submit()}
        />
        {err && <p className="text-sm text-rust">{err}</p>}
        <Button onClick={submit} loading={loading} className="w-full">
          进入
        </Button>
      </div>
    </Card>
  );
}
