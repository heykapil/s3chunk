import { Payload } from 'paseto-ts/lib/types';
import { decrypt, encrypt, sign, verify } from 'paseto-ts/v4';
// import { generateKeys } from 'paseto-ts/v4';

interface SignOption {
  addExp?: boolean;
  footer?: string;
}

interface Env {
  PASETO_PUBLIC_KEY: string;
  PASETO_SECRET_KEY: string;
  PASETO_LOCAL_KEY: string;
}

const DefaultSignOption: SignOption = {
  addExp: true,
  footer: 'kapil.app'
};

export async function signPasetoToken(
  env: Env,
  payload: Payload,
  options?: SignOption,
  key?: string
){
  try {
    const secretKey = key || env.PASETO_SECRET_KEY!;
    const token =  sign(secretKey, payload, options || DefaultSignOption);
    return token.slice(10); // Remove "v4.public." prefix
  } catch (e) {
    return null;
  }
}

export async function verifyPasetoToken(
  env: Env,
  token: string,
  key?: string
){
  try {
    const publicKey = key || env.PASETO_PUBLIC_KEY!;
    const encodedToken = `v4.public.${token}`;
    const { payload, footer } = verify(publicKey, encodedToken);
    return JSON.parse(JSON.stringify(payload));
  } catch (e) {
    return null;
  }
}

export async function encryptTokenV4(
  env: Env,
  payload: Payload,
  options?: SignOption
){
  try {
    const token = encrypt(
     env.PASETO_LOCAL_KEY!,
      payload,
      options || DefaultSignOption
    );
    return token.slice(9);
  } catch (e) {
    return null;
  }
}

export async function decryptTokenV4(
  env: Env,
  token: string
) {
  try {
    const encodedToken = `v4.local.${token}`;
    const { payload, footer } = decrypt( env.PASETO_LOCAL_KEY!, encodedToken);
    return JSON.parse(JSON.stringify(payload));
  } catch (e) {
    return null;
  }
}
