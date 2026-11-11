import { ElMessageBox } from "element-plus";
import { h, ref } from "vue";
import { isComposeHostPort } from "./composeHostPorts";

export interface PhpMyAdminServer {
  id: string;
  name: string;
}

export async function confirmPhpMyAdminInstall(port: number, servers: PhpMyAdminServer[], localUnavailable: boolean, parallel = false) {
  const hostPort = ref(String(port));
  const serverID = ref("");
  const error = ref("");
  await ElMessageBox({
    title: parallel ? "并行安装新版 phpMyAdmin" : "安装 phpMyAdmin",
    message: () => h("div", { style: { display: "grid", gap: "8px" } }, [
      parallel ? h("p", "新版使用独立回环端口。可选择现有 MySQL 实例，原管理入口继续运行。") : null,
      h("label", { for: "pma-install-port" }, "管理端口（服务器回环）"),
      h("input", {
        id: "pma-install-port", type: "number", min: 1024, max: 65535, value: hostPort.value,
        onInput: (event: Event) => { hostPort.value = (event.target as HTMLInputElement).value; error.value = ""; },
      }),
      h("label", { for: "pma-install-database" }, "数据库服务器"),
      h("select", {
        id: "pma-install-database", value: serverID.value,
        onChange: (event: Event) => { serverID.value = (event.target as HTMLSelectElement).value; error.value = ""; },
      }, [
        h("option", { value: "" }, "登录时输入外部数据库地址"),
        ...servers.map(server => h("option", { key: server.id, value: server.id }, server.name)),
      ]),
      localUnavailable ? h("p", "本机 MySQL 实例暂时无法核对。") : null,
      error.value ? h("p", { role: "alert" }, error.value) : null,
    ]),
    showCancelButton: true,
    confirmButtonText: "验签并安装",
    cancelButtonText: "取消",
    beforeClose(action, _instance, done) {
      if (action === "confirm" && !isComposeHostPort("phpmyadmin", Number(hostPort.value))) {
        error.value = "请输入 1024–65535 之间的本机端口。";
        return;
      }
      done();
    },
  });
  return { hostPort: Number(hostPort.value), serverID: serverID.value };
}
