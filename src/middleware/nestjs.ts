/**
 * NestJS adapter for Tork Governance
 *
 * Provides module, guard, and interceptor for NestJS applications.
 */

// PII patterns for governance
const PII_PATTERNS: Record<string, { pattern: RegExp; redaction: string }> = {
  ssn: { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, redaction: '[SSN_REDACTED]' },
  email: { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, redaction: '[EMAIL_REDACTED]' },
  phone: { pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, redaction: '[PHONE_REDACTED]' },
  creditCard: { pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, redaction: '[CARD_REDACTED]' },
};

export interface GovernanceResult {
  action: 'allow' | 'redact' | 'deny';
  output: string;
  hasPII: boolean;
  piiTypes: string[];
  receiptId: string;
}

export interface TorkNestJSOptions {
  governInput?: boolean;
  governOutput?: boolean;
  protectedRoutes?: string[];
  excludedRoutes?: string[];
}

/**
 * Govern text content
 */
function govern(input: string): GovernanceResult {
  let output = input;
  let hasPII = false;
  const piiTypes: string[] = [];

  for (const [type, config] of Object.entries(PII_PATTERNS)) {
    if (config.pattern.test(input)) {
      hasPII = true;
      piiTypes.push(type);
      output = output.replace(new RegExp(config.pattern.source, 'g'), config.redaction);
    }
  }

  return {
    action: hasPII ? 'redact' : 'allow',
    output,
    hasPII,
    piiTypes,
    receiptId: `rcpt_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
  };
}

/**
 * TorkNestJSModule - Dynamic module for NestJS
 *
 * @example
 * ```typescript
 * import { TorkNestJSModule } from 'tork-governance/middleware/nestjs';
 *
 * @Module({
 *   imports: [
 *     TorkNestJSModule.forRoot({
 *       governInput: true,
 *       governOutput: true,
 *     }),
 *   ],
 * })
 * export class AppModule {}
 * ```
 */
export class TorkNestJSModule {
  static options: TorkNestJSOptions = {};

  static forRoot(options: TorkNestJSOptions = {}) {
    this.options = {
      governInput: options.governInput ?? true,
      governOutput: options.governOutput ?? true,
      protectedRoutes: options.protectedRoutes ?? [],
      excludedRoutes: options.excludedRoutes ?? [],
    };

    return {
      module: TorkNestJSModule,
      providers: [
        {
          provide: 'TORK_OPTIONS',
          useValue: this.options,
        },
        TorkNestJSGuard,
        TorkNestJSInterceptor,
      ],
      exports: ['TORK_OPTIONS', TorkNestJSGuard, TorkNestJSInterceptor],
    };
  }

  static forFeature(options: Partial<TorkNestJSOptions> = {}) {
    return {
      module: TorkNestJSModule,
      providers: [
        {
          provide: 'TORK_FEATURE_OPTIONS',
          useValue: { ...this.options, ...options },
        },
      ],
    };
  }
}

/**
 * TorkNestJSGuard - Guard for protecting routes
 *
 * @example
 * ```typescript
 * import { TorkNestJSGuard } from 'tork-governance/middleware/nestjs';
 *
 * @Controller('users')
 * @UseGuards(TorkNestJSGuard)
 * export class UsersController {
 *   @Post()
 *   create(@Body() createUserDto: CreateUserDto) {
 *     // Request body is already governed
 *   }
 * }
 * ```
 */
export class TorkNestJSGuard {
  private options: TorkNestJSOptions;
  private receipts: GovernanceResult[] = [];

  constructor(options?: TorkNestJSOptions) {
    this.options = options || TorkNestJSModule.options;
  }

  canActivate(context: any): boolean {
    if (!this.options.governInput) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const path = request.path || request.url;

    // Check excluded routes
    if (this.options.excludedRoutes?.some(route => path.startsWith(route))) {
      return true;
    }

    // Govern request body
    if (request.body && typeof request.body === 'object') {
      this.governObject(request.body);
    }

    // Govern query parameters
    if (request.query && typeof request.query === 'object') {
      this.governObject(request.query);
    }

    return true;
  }

  private governObject(obj: Record<string, any>): void {
    for (const key of Object.keys(obj)) {
      if (typeof obj[key] === 'string') {
        const result = govern(obj[key]);
        obj[key] = result.output;
        this.receipts.push(result);

        if (result.action === 'deny') {
          throw new Error(`Request blocked by governance: ${result.receiptId}`);
        }
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        this.governObject(obj[key]);
      }
    }
  }

  getReceipts(): GovernanceResult[] {
    return [...this.receipts];
  }
}

/**
 * TorkNestJSInterceptor - Interceptor for governing responses
 *
 * @example
 * ```typescript
 * import { TorkNestJSInterceptor } from 'tork-governance/middleware/nestjs';
 *
 * @Controller('api')
 * @UseInterceptors(TorkNestJSInterceptor)
 * export class ApiController {
 *   @Get('data')
 *   getData() {
 *     return { email: 'user@example.com' }; // Will be redacted
 *   }
 * }
 * ```
 */
export class TorkNestJSInterceptor {
  private options: TorkNestJSOptions;
  private receipts: GovernanceResult[] = [];

  constructor(options?: TorkNestJSOptions) {
    this.options = options || TorkNestJSModule.options;
  }

  intercept(context: any, next: any): any {
    if (!this.options.governOutput) {
      return next.handle();
    }

    return {
      pipe: (operator: any) => {
        return next.handle().pipe({
          ...operator,
          next: (data: any) => {
            const governed = this.governResponse(data);
            operator.next(governed);
          },
        });
      },
    };
  }

  private governResponse(data: any): any {
    if (typeof data === 'string') {
      const result = govern(data);
      this.receipts.push(result);
      return result.output;
    }

    if (Array.isArray(data)) {
      return data.map(item => this.governResponse(item));
    }

    if (typeof data === 'object' && data !== null) {
      const governed: Record<string, any> = {};
      for (const [key, value] of Object.entries(data)) {
        governed[key] = this.governResponse(value);
      }
      return governed;
    }

    return data;
  }

  getReceipts(): GovernanceResult[] {
    return [...this.receipts];
  }
}

/**
 * Decorator for governed endpoints
 *
 * @example
 * ```typescript
 * @Controller('chat')
 * export class ChatController {
 *   @Post()
 *   @TorkGoverned()
 *   async chat(@Body() body: ChatDto) {
 *     // Input is governed
 *   }
 * }
 * ```
 */
export function TorkGoverned(options: Partial<TorkNestJSOptions> = {}) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      // Govern input arguments
      const governedArgs = args.map(arg => {
        if (typeof arg === 'string') {
          return govern(arg).output;
        }
        if (typeof arg === 'object' && arg !== null) {
          return governObject(arg);
        }
        return arg;
      });

      // Call original method
      let result = await originalMethod.apply(this, governedArgs);

      // Govern output if enabled
      if (options.governOutput !== false) {
        result = governValue(result);
      }

      return result;
    };

    return descriptor;
  };
}

function governObject(obj: Record<string, any>): Record<string, any> {
  const governed: Record<string, any> = {};
  for (const [key, value] of Object.entries(obj)) {
    governed[key] = governValue(value);
  }
  return governed;
}

function governValue(value: any): any {
  if (typeof value === 'string') {
    return govern(value).output;
  }
  if (Array.isArray(value)) {
    return value.map(governValue);
  }
  if (typeof value === 'object' && value !== null) {
    return governObject(value);
  }
  return value;
}

/**
 * Create a governed pipe for NestJS
 */
export function createTorkPipe() {
  return {
    transform(value: any) {
      if (typeof value === 'string') {
        return govern(value).output;
      }
      if (typeof value === 'object' && value !== null) {
        return governObject(value);
      }
      return value;
    },
  };
}

export default TorkNestJSModule;
