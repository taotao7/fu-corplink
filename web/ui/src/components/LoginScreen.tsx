import { useEffect, useState } from "react";
import { api, ApiError, type LoginMethods, type TpsOption } from "../api";
import { Card, Input } from "../ui/Card";
import { Button } from "../ui/Button";
import { KeyRound, Mail, ExternalLink, ArrowLeft } from "lucide-react";

type Tab = "password" | "email" | "sso";

export function LoginScreen({
  onLoggedIn,
  onBack,
}: {
  onLoggedIn: () => void;
  onBack: () => void;
}) {
  const [methods, setMethods] = useState<LoginMethods | null>(null);
  const [tab, setTab] = useState<Tab>("password");

  useEffect(() => {
    api
      .loginMethods()
      .then((m) => {
        setMethods(m);
        if (m.tps && m.tps.length > 0 && !(m.login_enable || m.login_enable_ldap)) {
          setTab("sso");
        }
      })
      .catch(() => setMethods({ login_orders: [], login_enable: true, login_enable_ldap: false, tps: [] }));
  }, []);

  const tps = methods?.tps ?? [];

  return (
    <Card>
      <button
        onClick={onBack}
        className="mb-4 inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-700"
      >
        <ArrowLeft className="h-4 w-4" /> 重新输入企业代号
      </button>
      <h2 className="mb-4 text-base font-semibold text-slate-900">登录</h2>

      <div className="mb-5 flex gap-1 rounded-xl bg-slate-100 p-1">
        <TabButton active={tab === "password"} onClick={() => setTab("password")}>
          <KeyRound className="h-4 w-4" /> 密码
        </TabButton>
        <TabButton active={tab === "email"} onClick={() => setTab("email")}>
          <Mail className="h-4 w-4" /> 邮箱验证码
        </TabButton>
        {tps.length > 0 && (
          <TabButton active={tab === "sso"} onClick={() => setTab("sso")}>
            <ExternalLink className="h-4 w-4" /> SSO
          </TabButton>
        )}
      </div>

      {tab === "password" && (
        <PasswordForm ldap={methods?.login_enable_ldap ?? false} onLoggedIn={onLoggedIn} />
      )}
      {tab === "email" && <EmailForm onLoggedIn={onLoggedIn} />}
      {tab === "sso" && <SsoForm options={tps} onLoggedIn={onLoggedIn} />}
    </Card>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex flex-1 items-center justify-center gap-1.5 rounded-lg px-3 py-2 text-sm font-medium transition ${
        active ? "bg-white text-blue-600 shadow-sm" : "text-slate-500 hover:text-slate-700"
      }`}
    >
      {children}
    </button>
  );
}

function PasswordForm({
  ldap,
  onLoggedIn,
}: {
  ldap: boolean;
  onLoggedIn: () => void;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [platform, setPlatform] = useState("feilian");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  async function submit() {
    setLoading(true);
    setErr("");
    try {
      await api.loginPassword(username, password, platform);
      onLoggedIn();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "登录失败");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      <Input label="用户名" value={username} autoFocus onChange={(e) => setUsername(e.target.value)} />
      <Input
        label="密码"
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && submit()}
      />
      <label className="block">
        <span className="mb-1.5 block text-sm font-medium text-slate-600">登录方式</span>
        <select
          value={platform}
          onChange={(e) => setPlatform(e.target.value)}
          className="w-full rounded-xl border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none focus:border-blue-400 focus:ring-2 focus:ring-blue-100"
        >
          <option value="feilian">飞连密码</option>
          <option value="feilian_v1">飞连密码 (v1)</option>
          {ldap && <option value="ldap">LDAP</option>}
        </select>
      </label>
      {err && <p className="text-sm text-rose-600">{err}</p>}
      <Button onClick={submit} loading={loading} className="w-full">
        登录
      </Button>
    </div>
  );
}

function EmailForm({ onLoggedIn }: { onLoggedIn: () => void }) {
  const [username, setUsername] = useState("");
  const [code, setCode] = useState("");
  const [sent, setSent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  async function sendCode() {
    setLoading(true);
    setErr("");
    try {
      await api.emailRequest(username);
      setSent(true);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "发送验证码失败");
    } finally {
      setLoading(false);
    }
  }

  async function verify() {
    setLoading(true);
    setErr("");
    try {
      await api.emailVerify(username, code);
      onLoggedIn();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "验证码校验失败");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      <Input
        label="用户名 / 邮箱"
        value={username}
        autoFocus
        onChange={(e) => setUsername(e.target.value)}
      />
      {sent && (
        <Input
          label="邮箱验证码"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && verify()}
        />
      )}
      {err && <p className="text-sm text-rose-600">{err}</p>}
      {!sent ? (
        <Button onClick={sendCode} loading={loading} className="w-full">
          发送验证码
        </Button>
      ) : (
        <div className="flex gap-2">
          <Button variant="secondary" onClick={sendCode} loading={loading}>
            重新发送
          </Button>
          <Button onClick={verify} loading={loading} className="flex-1">
            登录
          </Button>
        </div>
      )}
    </div>
  );
}

function SsoForm({
  options,
  onLoggedIn,
}: {
  options: TpsOption[];
  onLoggedIn: () => void;
}) {
  const [polling, setPolling] = useState<string | null>(null);

  function startSso(opt: TpsOption) {
    window.open(opt.login_url, "_blank", "noopener,noreferrer");
    setPolling(opt.token);
    const timer = setInterval(async () => {
      try {
        const r = await api.tpsCheck(opt.token);
        if (r.ok) {
          clearInterval(timer);
          setPolling(null);
          onLoggedIn();
        }
      } catch {
        /* keep polling */
      }
    }, 2000);
  }

  return (
    <div className="space-y-3">
      <p className="text-sm text-slate-500">
        点击下方按钮在新标签页完成第三方登录，完成后会自动继续。
      </p>
      {options.map((o) => (
        <Button
          key={o.token}
          variant="secondary"
          className="w-full justify-between"
          onClick={() => startSso(o)}
          loading={polling === o.token}
        >
          <span>{o.alias || "第三方登录"}</span>
          <ExternalLink className="h-4 w-4" />
        </Button>
      ))}
      {options.length === 0 && (
        <p className="text-sm text-slate-400">当前没有可用的 SSO 登录方式</p>
      )}
    </div>
  );
}
