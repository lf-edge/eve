// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.

package verifier

func handleVerifyImageConfigModify(ctxArg interface{}, key string, configArg interface{}, oldConfigArg interface{}) {
	vHandler.modify(ctxArg, key, configArg, oldConfigArg)
}

func handleVerifyImageConfigCreate(ctxArg interface{}, key string, configArg interface{}) {
	vHandler.create(ctxArg, key, configArg)
}

func handleVerifyImageConfigDelete(ctxArg interface{}, key string, configArg interface{}) {
	vHandler.delete(ctxArg, key, configArg)
}
