export interface ParsedCliArguments {
  command?: string;
  target?: string;
  flags: string[];
}

export function parseCliArguments(args: string[]): ParsedCliArguments {
  const [command, ...rest] = args;
  if (command === "scan" || command === "remote-preflight") {
    const [target, ...flags] = rest;
    return { command, target, flags };
  }
  return { command, flags: rest };
}
