/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { login } from '../../routes/login'
import * as models from '../../models/index'
import * as security from '../../lib/insecurity'
const expect = chai.expect
chai.use(sinonChai)

describe('login', () => {
  let req: any
  let res: any
  let next: sinon.SinonSpy
  let queryStub: sinon.SinonStub

  beforeEach(() => {
    req = { body: {} }
    res = { json: sinon.spy(), status: sinon.stub().returnsThis(), send: sinon.spy(), __: (s: string) => s }
    next = sinon.spy()
    // no user found => 401 path, no further DB access needed
    queryStub = sinon.stub(models.sequelize, 'query').resolves(null as any)
  })

  afterEach(() => {
    queryStub.restore()
  })

  it('should pass email and password hash as bound replacements instead of embedding them in the SQL', () => {
    req.body = { email: 'jim@juice-sh.op', password: 'ncc-1701' }

    login()(req, res, next)

    expect(queryStub).to.have.been.calledOnce
    const [sql, options] = queryStub.firstCall.args as [string, any]
    expect(sql).to.equal('SELECT * FROM Users WHERE email = ? AND password = ? AND deletedAt IS NULL')
    expect(options.replacements).to.deep.equal(['jim@juice-sh.op', security.hash('ncc-1701')])
  })

  it('should keep SQL injection payloads in email out of the SQL text', () => {
    const payload = "' OR true --"
    req.body = { email: payload, password: 'whatever' }

    login()(req, res, next)

    const [sql, options] = queryStub.firstCall.args as [string, any]
    expect(sql).to.not.contain(payload)
    expect(sql).to.not.contain('OR true')
    expect(options.replacements[0]).to.equal(payload)
  })

  it('should use empty strings when email and password are missing', () => {
    login()(req, res, next)

    const [, options] = queryStub.firstCall.args as [string, any]
    expect(options.replacements).to.deep.equal(['', security.hash('')])
  })

  it('should respond with 401 when no user matches', async () => {
    req.body = { email: "' OR true --", password: 'x' }

    login()(req, res, next)
    await new Promise(resolve => setImmediate(resolve))

    expect(res.status).to.have.been.calledWith(401)
    expect(next).to.not.have.been.called
  })
})
