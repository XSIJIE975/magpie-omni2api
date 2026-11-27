// 灵码账号的凭据形状。登录材料来自浏览器登录回调（securityOauthToken/
// refreshToken）；B 族签名材料（key / encryptUserInfo）由本地按
// machineId + uid 合成。

// auth 记录里属于本 provider 的字段（不含 type：登录结果交给宿主时是
// type:"success"，落盘由宿主改写成 type:"oauth"）：
// { refresh:<refreshToken>, access:<securityOauthToken>, expires:<expireTimeMs>,
//   accountId:"<uid>|<orgId>", uid, name, userType, organizationId, organizationName,
//   key, encryptUserInfo, machineId, refreshToken, securityOauthToken, expireTimeMs }
export function buildAuth(login, materials, machineId) {
  return {
    refresh: login.refreshToken,
    access: login.securityOauthToken,
    expires: login.expireTimeMs || 0,
    accountId: `${login.uid}|${login.orgId}`,
    uid: login.uid,
    name: login.name,
    userType: login.userType,
    organizationId: login.orgId,
    organizationName: login.orgName,
    key: materials.key,
    encryptUserInfo: materials.encryptUserInfo,
    machineId,
    refreshToken: login.refreshToken,
    securityOauthToken: login.securityOauthToken,
    expireTimeMs: login.expireTimeMs || 0,
  };
}

// B 族签名材料齐备。
export function hasMaterial(auth) {
  return !!(auth?.key && auth?.encryptUserInfo);
}
