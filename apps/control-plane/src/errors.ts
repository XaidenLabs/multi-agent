export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail: string;
  requestId: string;
  fieldErrors?: Record<string, string[]>;
}

export class ApiProblem extends Error {
  constructor(
    readonly status: number,
    readonly type: string,
    readonly title: string,
    detail: string,
    readonly fieldErrors?: Record<string, string[]>,
  ) {
    super(detail);
  }
}
