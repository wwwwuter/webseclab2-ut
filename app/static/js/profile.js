/* ===========================================================
   个人中心 (Profile) 脚本
   - 编辑页（/profile/edit）：头像即时上传 + 资料/密码 AJAX 提交
   - 主页（/profile）：所有修改通过 Bootstrap Modal 完成，不跳转页面
   - 成功提示「修改成功」/ 失败提示「修改失败」（优先展示后端具体原因）
   =========================================================== */
(function () {
    'use strict';

    var token = '';
    var meta = document.querySelector('meta[name="csrf-token"]');
    if (meta) token = meta.getAttribute('content');

    function notify(msg, category) {
        if (window.showNotification) window.showNotification(msg, category || 'info');
    }

    function postJSON(url, data) {
        return fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': token },
            credentials: 'same-origin',
            body: JSON.stringify(data)
        }).then(function (r) { return r.json(); });
    }

    function postForm(url, fd) {
        var headers = {};
        if (token) headers['X-CSRFToken'] = token;
        return fetch(url, {
            method: 'POST',
            headers: headers,
            credentials: 'same-origin',
            body: fd
        }).then(function (r) { return r.json(); });
    }

    function closeModal(id) {
        var el = document.getElementById(id);
        if (el && window.bootstrap) {
            var inst = bootstrap.Modal.getInstance(el);
            if (inst) inst.hide();
        }
    }

    function spin(btn, loading, label) {
        if (!btn) return;
        btn.disabled = loading;
        btn.innerHTML = loading
            ? '<span class="spinner-border spinner-border-sm"></span> ' + (label || '处理中...')
            : (label || '<i class="bi bi-check-lg"></i> 保存');
    }

    /* =========================================================
       编辑页（/profile/edit）：头像 + 资料 + 密码
       ========================================================= */

    /* 头像：预览 + 立即上传 */
    var avatarInput = document.getElementById('avatar-input');
    if (avatarInput) {
        avatarInput.addEventListener('change', function () {
            var file = this.files[0];
            if (!file) return;

            var reader = new FileReader();
            reader.onload = function (e) {
                var wrap = document.querySelector('.profile-avatar.lg');
                var preview = document.getElementById('avatar-preview');
                if (!preview) {
                    wrap.innerHTML = '<img src="" id="avatar-preview" alt="头像">';
                    preview = document.getElementById('avatar-preview');
                }
                preview.src = e.target.result;
            };
            reader.readAsDataURL(file);

            var fd = new FormData();
            fd.append('avatar', file);
            var headers = {};
            if (token) headers['X-CSRFToken'] = token;
            fetch('/profile/api/avatar', {
                method: 'POST',
                headers: headers,
                credentials: 'same-origin',
                body: fd
            })
            .then(function (r) { return r.json(); })
            .then(function (res) {
                if (!res.ok) { notify(res.msg || '头像上传失败', 'danger'); return; }
                var pv = document.getElementById('avatar-preview');
                if (pv && res.url) pv.src = res.url;
                notify(res.msg || '头像已更新', 'success');
            })
            .catch(function () { notify('头像上传失败，请重试', 'danger'); });
        });
    }

    /* 保存修改（编辑页） */
    var saveBtn = document.getElementById('save-btn');
    if (saveBtn) {
        saveBtn.addEventListener('click', function () {
            var nickname = document.getElementById('nickname').value.trim();
            var email = document.getElementById('email').value.trim();
            var pwCurrent = document.getElementById('pw-current').value;
            var pwNew = document.getElementById('pw-new').value;
            var pwConfirm = document.getElementById('pw-confirm').value;
            var mismatch = document.getElementById('pw-mismatch');

            if (pwNew || pwCurrent) {
                if (pwNew !== pwConfirm) {
                    if (mismatch) mismatch.classList.remove('d-none');
                    notify('两次输入的新密码不一致', 'danger');
                    return;
                }
                if (mismatch) mismatch.classList.add('d-none');
            }

            spin(saveBtn, true, '保存中...');

            var chain = Promise.resolve();
            if (pwNew) {
                chain = chain.then(function () {
                    return postJSON('/profile/api/change-password', {
                        current: pwCurrent, new: pwNew, confirm: pwConfirm
                    }).then(function (res) {
                        if (!res.ok) throw new Error(res.msg || '密码修改失败');
                    });
                });
            }
            chain = chain.then(function () {
                return postJSON('/profile/api/update', { nickname: nickname, email: email })
                    .then(function (res) {
                        if (!res.ok) throw new Error(res.msg || '保存失败');
                        notify('保存成功', 'success');
                        setTimeout(function () { window.location.href = '/profile'; }, 700);
                    });
            });

            chain.catch(function (err) {
                notify(err.message || '保存失败，请重试', 'danger');
                spin(saveBtn, false);
            });
        });
    }

    /* =========================================================
       主页（/profile）：Modal 驱动的修改
       ========================================================= */

    /* ---- 修改资料 Modal ---- */
    var miSave = document.getElementById('mi-save');
    if (miSave) {
        miSave.addEventListener('click', function () {
            var nickname = document.getElementById('mi-nickname').value.trim();
            var email = document.getElementById('mi-email').value.trim();
            spin(miSave, true, '保存中...');
            postJSON('/profile/api/update', { nickname: nickname, email: email })
                .then(function (res) {
                    if (!res.ok) throw new Error(res.msg || '修改失败');
                    // 就地更新展示
                    document.getElementById('v-nickname').textContent = nickname || '未设置';
                    document.getElementById('v-email').textContent = email || '未设置';
                    var nameEl = document.getElementById('profile-name');
                    if (nickname) {
                        nameEl.innerHTML = nickname + ' <small class="text-muted">@{{ user.username }}</small>';
                    } else {
                        nameEl.textContent = '{{ user.username }}';
                    }
                    // 头像字母
                    var mainAv = document.querySelector('.profile-avatar-col .profile-avatar');
                    if (mainAv && !mainAv.querySelector('img')) {
                        var sp = mainAv.querySelector('span');
                        if (sp) sp.textContent = (nickname || '{{ user.username }}')[0].toUpperCase();
                    }
                    notify('修改成功', 'success');
                    closeModal('editInfoModal');
                })
                .catch(function (err) { notify(err.message || '修改失败', 'danger'); })
                .finally(function () { spin(miSave, false); });
        });
    }

    /* ---- 修改密码 Modal ---- */
    var cpwSave = document.getElementById('cpw-save');
    if (cpwSave) {
        cpwSave.addEventListener('click', function () {
            var cur = document.getElementById('cpw-current').value;
            var nw = document.getElementById('cpw-new').value;
            var cf = document.getElementById('cpw-confirm').value;
            var mismatch = document.getElementById('cpw-mismatch');

            if (nw || cur) {
                if (nw !== cf) {
                    if (mismatch) mismatch.classList.remove('d-none');
                    notify('两次输入的新密码不一致', 'danger');
                    return;
                }
                if (mismatch) mismatch.classList.add('d-none');
            }

            spin(cpwSave, true, '保存中...');
            postJSON('/profile/api/change-password', { current: cur, new: nw, confirm: cf })
                .then(function (res) {
                    if (!res.ok) throw new Error(res.msg || '修改失败');
                    notify('修改成功', 'success');
                    closeModal('changePwModal');
                    var f = document.getElementById('cpw-form');
                    if (f) f.reset();
                })
                .catch(function (err) { notify(err.message || '修改失败', 'danger'); })
                .finally(function () { spin(cpwSave, false); });
        });
    }

    /* ---- 修改头像 Modal ---- */
    var avInput = document.getElementById('av-input');
    var avSave = document.getElementById('av-save');
    if (avInput && avSave) {
        var avFile = null;
        avSave.disabled = true;

        avInput.addEventListener('change', function () {
            var file = this.files[0];
            if (!file) { avFile = null; avSave.disabled = true; return; }
            avFile = file;
            var reader = new FileReader();
            reader.onload = function (e) {
                var wrap = document.getElementById('av-preview-wrap');
                wrap.innerHTML = '<img src="" id="av-preview" alt="头像">';
                document.getElementById('av-preview').src = e.target.result;
            };
            reader.readAsDataURL(file);
            avSave.disabled = false;
        });

        avSave.addEventListener('click', function () {
            if (!avFile) { notify('请先选择图片', 'warning'); return; }
            var fd = new FormData();
            fd.append('avatar', avFile);
            spin(avSave, true, '上传中...');
            postForm('/profile/api/avatar', fd)
                .then(function (res) {
                    if (!res.ok) throw new Error(res.msg || '修改失败');
                    var mainAv = document.querySelector('.profile-avatar-col .profile-avatar');
                    if (mainAv && res.url) mainAv.innerHTML = '<img src="' + res.url + '" alt="头像">';
                    notify('修改成功', 'success');
                    closeModal('avatarModal');
                })
                .catch(function (err) { notify(err.message || '修改失败', 'danger'); })
                .finally(function () { spin(avSave, false); });
        });
    }
})();
