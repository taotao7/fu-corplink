import { useState } from "react";
import { api, ApiError } from "../api";
import { Card, Input } from "../ui/Card";
import { Button } from "../ui/Button";
import { Building2 } from "lucide-react";

export function CompanyScreen({ onDone }: { onDone: () => void }) {
  const [code, setCode] = useState("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  async function submit() {
    if (!code.trim()) return;
    setLoading(true);
    setErr("");
    try {
      await api.setCompany(code.trim());
      onDone();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "解析企业代号失败");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card>
      <div className="mb-5 flex items-center gap-3">
        <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-blue-50 text-blue-600">
          <Building2 className="h-5 w-5" />
        </div>
        <div>
          <h2 className="text-base font-semibold text-slate-900">输入企业代号</h2>
          <p className="text-sm text-slate-500">用于定位你所在企业的飞连服务器</p>
        </div>
      </div>
      <div className="space-y-4">
        <Input
          label="企业代号 / Company code"
          placeholder="例如 your-company"
          value={code}
          autoFocus
          onChange={(e) => setCode(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submit()}
        />
        {err && <p className="text-sm text-rose-600">{err}</p>}
        <Button onClick={submit} loading={loading} className="w-full">
          下一步
        </Button>
      </div>
    </Card>
  );
}
