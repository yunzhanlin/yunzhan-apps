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
    case "php-legacy-81-bookworm-compat2":
      return { preferred: 18082, max: 65535, usesNextPort: false, detail: "" };
    case "php-legacy-80-bullseye-compat2":
      return { preferred: 18083, max: 65535, usesNextPort: false, detail: "" };
    case "php-legacy-74-bullseye-compat3":
      return { preferred: 18084, max: 65535, usesNextPort: false, detail: "" };
    case "php-legacy-54-bookworm-compat3":
      return { preferred: 18085, max: 65535, usesNextPort: false, detail: "" };
    case "php-legacy-55-bookworm-compat3":
      return { preferred: 18086, max: 65535, usesNextPort: false, detail: "" };
    case "php-legacy-56-stretch-compat3":
      return { preferred: 18087, max: 65535, usesNextPort: false, detail: "" };
    case "php-legacy-70-stretch-compat3":
      return { preferred: 18088, max: 65535, usesNextPort: false, detail: "" };
    case "php-legacy-71-stretch-compat3":
      return { preferred: 18089, max: 65535, usesNextPort: false, detail: "" };
    case "php-legacy-72-buster-compat3":
      return { preferred: 18090, max: 65535, usesNextPort: false, detail: "" };
    case "php-legacy-73-buster-compat3":
      return { preferred: 18091, max: 65535, usesNextPort: false, detail: "" };
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
