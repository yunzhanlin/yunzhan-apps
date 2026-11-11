export function composeHostPortSettings(template: string) {
  switch (template) {
    case "rabbitmq":
      return { preferred: 15672, max: 65534, usesNextPort: true, detail: "起始端口用于 RabbitMQ 管理界面，下一个端口用于 AMQP 消息连接。" };
    case "openlitespeed":
      return { preferred: 18888, max: 65534, usesNextPort: true, detail: "起始端口用于网站 HTTP，下一个端口用于 WebAdmin HTTPS。" };
    case "openlitespeed-194":
      return { preferred: 18890, max: 65534, usesNextPort: true, detail: "起始端口用于网站 HTTP，下一个端口用于 WebAdmin HTTPS。" };
    case "memcached-cache":
      return { preferred: 21211, max: 65535, usesNextPort: false, detail: "" };
    case "mongodb":
      return { preferred: 27017, max: 65535, usesNextPort: false, detail: "" };
    case "elasticsearch":
      return { preferred: 19200, max: 65535, usesNextPort: false, detail: "" };
    case "phpmyadmin-523":
      return { preferred: 18081, max: 65535, usesNextPort: false, detail: "" };
    default:
      return { preferred: 18080, max: 65535, usesNextPort: false, detail: "" };
  }
}

export function isPhpMyAdminTemplate(template?: string): boolean {
  return template === "phpmyadmin" || template === "phpmyadmin-523";
}

export function isComposeHostPort(template: string, value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) &&
    value >= 1024 && value <= composeHostPortSettings(template).max;
}
