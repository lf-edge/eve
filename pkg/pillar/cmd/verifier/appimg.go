// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.

package verifier

// wrappers to add objType for create. The Delete wrappers are merely
// for function name consistency
func handleVerifyImageConfigModify(ctxArg interface{}, key string, configArg interface{}) {
	vHandler.modify(ctxArg, key, configArg)
}

func handleVerifyImageConfigCreate(ctxArg interface{}, key string, configArg interface{}) {
	vHandler.create(ctxArg, key, configArg)
}

func handleVerifyImageConfigDelete(ctxArg interface{}, key string, configArg interface{}) {
	vHandler.delete(ctxArg, key, configArg)
}
