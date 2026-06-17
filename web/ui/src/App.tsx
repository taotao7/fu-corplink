import { useCallback, useEffect, useState } from "react";
import { api, type State, type Server } from "./api";
import { Header } from "./components/Header";
import { CompanyScreen } from "./components/CompanyScreen";
import { LoginScreen } from "./components/LoginScreen";
import { NodeList } from "./components/NodeList";
import { ConnectionPanel } from "./components/ConnectionPanel";
import { SettingsDialog } from "./components/SettingsDialog";
import { AdminGate } from "./components/AdminGate";
import { Card } from "./ui/Card";
import { Button } from "./ui/Button";
import { Settings, LogOut } from "lucide-react";

export default function App() {
  const [state, setState] = useState<State | null>(null);
  const [adminOK, setAdminOK] = useState<boolean | null>(null);
  const [servers, setServers] = useState<Server[]>([]);
  const [loadingServers, setLoadingServers] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [otpPrompt, setOtpPrompt] = useState(false);
  const [otp, setOtp] = useState("");
  const [notice, setNotice] = useState("");
  // override the company/login flow when the user explicitly goes back
  const [forceCompany, setForceCompany] = useState(false);

  const refreshState = useCallback(async () => {
    try {
      setState(await api.state());
    } catch {
      /* keep last */
    }
  }, []);

  // admin gate check (once)
  useEffect(() => {
    api
      .adminAuth()
      .then((a) => setAdminOK(!a.enabled || a.authenticated))
      .catch(() => setAdminOK(true));
  }, []);

  // poll state every 2s once past the admin gate
  useEffect(() => {
    if (adminOK !== true) return;
    refreshState();
    const id = setInterval(refreshState, 2000);
    return () => clearInterval(id);
  }, [adminOK, refreshState]);

  const loadServers = useCallback(async (probe: boolean) => {
    setLoadingServers(true);
    try {
      const r = await api.servers(probe);
      setServers(r.servers);
    } catch (e) {
      setNotice(e instanceof Error ? e.message : "加载节点失败");
    } finally {
      setLoadingServers(false);
    }
  }, []);

  // when logged in, load the node list once
  const loggedIn =
    state &&
    (state.state === "logged_in" ||
      state.state === "connected" ||
      state.state === "connecting" ||
      state.state === "disconnecting");

  useEffect(() => {
    if (loggedIn && servers.length === 0) {
      loadServers(true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loggedIn]);

  async function doConnect(serverId: number, code?: string) {
    setConnecting(true);
    setNotice("");
    try {
      const r = await api.connect(serverId, code);
      if (r.need_otp) {
        setOtpPrompt(true);
        return;
      }
      setOtpPrompt(false);
      setOtp("");
      await refreshState();
    } catch (e) {
      setNotice(e instanceof Error ? e.message : "连接失败");
    } finally {
      setConnecting(false);
    }
  }

  async function pin(id: number) {
    await api.putConfig({ vpn_server_id: id });
    setServers((prev) => prev.map((s) => ({ ...s, selected: s.id === id })));
    refreshState();
  }

  async function logout() {
    await api.logout();
    setServers([]);
    setForceCompany(false);
    refreshState();
  }

  // --- render gates ---
  if (adminOK === null) return <Shell>{null}</Shell>;
  if (adminOK === false)
    return (
      <Shell>
        <AdminGate onAuthed={() => setAdminOK(true)} />
      </Shell>
    );

  const needCompany = !state || state.need_company || forceCompany;

  return (
    <Shell state={state}>
      {needCompany ? (
        <CompanyScreen
          onDone={() => {
            setForceCompany(false);
            refreshState();
          }}
        />
      ) : !loggedIn ? (
        <LoginScreen
          onLoggedIn={refreshState}
          onBack={() => setForceCompany(true)}
        />
      ) : (
        <div className="space-y-4">
          <Card>
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h2 className="text-base font-semibold text-slate-900">连接</h2>
                <p className="text-sm text-slate-500">{state!.username}</p>
              </div>
              <div className="flex gap-2">
                <Button variant="ghost" onClick={() => setSettingsOpen(true)}>
                  <Settings className="h-4 w-4" /> 设置
                </Button>
                <Button variant="ghost" onClick={logout}>
                  <LogOut className="h-4 w-4" /> 退出
                </Button>
              </div>
            </div>
            <ConnectionPanel state={state!} onChanged={refreshState} />
          </Card>

          {state!.state !== "connected" && (
            <Card>
              <div className="mb-3 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-slate-700">选择节点</h3>
              </div>
              <NodeList
                servers={servers}
                pinnedId={state!.server_id}
                loading={loadingServers}
                onPin={pin}
                onRefresh={() => loadServers(true)}
              />
              <div className="mt-4">
                <Button
                  className="w-full"
                  loading={connecting}
                  onClick={() => doConnect(state!.server_id)}
                >
                  {state!.server_id
                    ? `连接 ${
                        servers.find((s) => s.id === state!.server_id)?.name ||
                        servers.find((s) => s.id === state!.server_id)?.en_name ||
                        "所选节点"
                      }`
                    : "自动选择并连接"}
                </Button>
                <p className="mt-2 text-center text-xs text-slate-400">
                  {state!.server_id
                    ? "已选定节点，点击上方按钮连接"
                    : "点击列表中的节点可指定，不选则自动挑选"}
                </p>
              </div>
            </Card>
          )}

          {notice && (
            <p className="rounded-xl bg-rose-50 px-4 py-2 text-sm text-rose-600">
              {notice}
            </p>
          )}
        </div>
      )}

      <SettingsDialog open={settingsOpen} onClose={() => setSettingsOpen(false)} />

      {otpPrompt && (
        <OtpDialog
          value={otp}
          onChange={setOtp}
          loading={connecting}
          onCancel={() => setOtpPrompt(false)}
          onSubmit={() => doConnect(state!.server_id, otp)}
        />
      )}
    </Shell>
  );
}

function Shell({
  children,
  state,
}: {
  children: React.ReactNode;
  state?: State | null;
}) {
  return (
    <div className="mx-auto flex min-h-full max-w-lg flex-col px-4 py-10">
      <Header state={state ?? null} />
      {children}
      <footer className="mt-auto pt-10 text-center text-xs text-slate-400">
        fu-corplink · 非官方第三方实现
      </footer>
    </div>
  );
}

function OtpDialog({
  value,
  onChange,
  loading,
  onCancel,
  onSubmit,
}: {
  value: string;
  onChange: (v: string) => void;
  loading: boolean;
  onCancel: () => void;
  onSubmit: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-slate-900/30 backdrop-blur-sm" onClick={onCancel} />
      <Card className="relative z-10 w-full max-w-sm">
        <h2 className="mb-2 text-base font-semibold text-slate-900">输入 2FA 验证码</h2>
        <p className="mb-4 text-sm text-slate-500">该节点需要 6 位动态验证码</p>
        <input
          autoFocus
          inputMode="numeric"
          maxLength={6}
          value={value}
          onChange={(e) => onChange(e.target.value.replace(/\D/g, ""))}
          onKeyDown={(e) => e.key === "Enter" && onSubmit()}
          className="mb-4 w-full rounded-xl border border-slate-200 px-3.5 py-2.5 text-center text-lg tracking-[0.4em] outline-none focus:border-blue-400 focus:ring-2 focus:ring-blue-100"
          placeholder="000000"
        />
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={onCancel}>
            取消
          </Button>
          <Button loading={loading} onClick={onSubmit}>
            连接
          </Button>
        </div>
      </Card>
    </div>
  );
}
