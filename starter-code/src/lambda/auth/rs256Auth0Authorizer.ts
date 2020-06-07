
import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'
import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const cert  = `-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJAU4jARpDvN3VMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
BAMTFmRldi0xbnQwdjJjMS5hdXRoMC5jb20wHhcNMjAwNjA3MDU1MTEyWhcNMzQw
MjE0MDU1MTEyWjAhMR8wHQYDVQQDExZkZXYtMW50MHYyYzEuYXV0aDAuY29tMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0W80Os+t6SK4RroCeqHU9qG+

....cert code here....

jhMGLw7Mda5dgJSNWzRmRw5/LW7DQ26okVv4HyayOgbRffPJE
gAM+SAGbYJ1DsMc2+FkfRb5e9EQZACFoRMszdjdVxItn5aSpetKmwDrYcGgxcS63
gmcd9ojweQdbWeCPFjT56gQ641cjYsgAGfTFwScKCfKruwJG2/rfUu7iSAjvgWpe
LrOMTEHZ/NUB0Ko7xE9TGcp/WlVWbyKbRXvRc/W9KqWFSgdky5wtIGGQVDwMUyV3
J304t9eWCC17v58=
-----END CERTIFICATE-----`

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  try {
    const decodedToken = verifyToken(event.authorizationToken)
    console.log('User was authorized', decodedToken)

    return {
      principalId: decodedToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User was not authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

function verifyToken(authHeader: string): JwtToken {
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  const decodedToken = verify(
    token, 
    cert,                     
    { algorithms: ['RS256'] } 
  ) as JwtToken

  return decodedToken
}
