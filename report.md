# Kernel security fast-track

## 6.18 (base 6.18.60, `f45ed76d6791`)

Already in tree: 148 · Other architectures (not built): 5 · cve/ backports no longer needed: 3

### Included (119)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
|  | CVE-2026-98439 | `4fd5bad647bf` | stable-queue | smb/server: cancel async requests when closing connection |
|  | CVE-2026-53024 | `84265cbd96b9` | mainline | greybus: raw: fix use-after-free if write is called after disconnect |
|  | CVE-2026-46017 | `3bac01168982` | mainline | mm: fix deferred split queue races during migration |
|  | CVE-2026-98376 | `593980175389` | mainline | bpf: Use array_map_meta_equal for percpu array inner map replacement |
|  | CVE-2026-93044 | `34746b5a84ec` | mainline | bpf: Disallow interpreter fallback for arena-related insns |
|  | CVE-2026-90256 | `2b66c83ff175` | mainline | Bluetooth: L2CAP: use proto_lock for l2cap_data to fix l2cap_disconn_ind |
|  | CVE-2026-80579 | `95e647d2a530` | mainline | fbdev: clear fb_info->mode before deleting a videomode |
|  | CVE-2026-80580 | `d15d51fb26e8` | mainline | fbdev: bound mode sysfs output to the sysfs buffer |
|  | CVE-2026-100072 | `a9ba4dd2f18b` | mainline | ACPI: platform: Use acpi_bus_get_primary_device() |
|  | CVE-2026-98364 | `9fa903b24b1f` | mainline | xfrm: hold net_device reference under RCU in bundle creation |
|  | CVE-2026-98355 | `99c24a8968eb` | mainline | RDMA/rtrs: guard against null kobj name |
|  | CVE-2026-98834 | `26300879cd8e` | mainline | mtd: core: avoid double-free of OTP NVMEM device |
|  | CVE-2026-98332 | `6f0a100df853` | mainline | wifi: mac80211: only operate on TDLS peers in the TDLS code |
|  | CVE-2026-98292 | `8879e3e0a84a` | mainline | Bluetooth: btmtksdio, btmtkuart: validate WMT event length before struct access |
|  | CVE-2026-98285 | `2842ce397dd0` | mainline | net: bridge: vlan: fix bugs caused by switchdev deletion errors |
|  | CVE-2026-98824 | `6bdcdb31318c` | mainline | wifi: mac80211: validate TX status rate metadata |
|  | CVE-2026-98551 | `24b620729e53` | mainline | perf/core: Fill branch entries with a single assignment |
|  | CVE-2026-98570 | `87cd6b717e40` | mainline | net: ipv6: keep room for the mac header in dst_dev_overhead() |
|  | CVE-2026-98810 | `6f63e919fe1e` | mainline | wifi: mac80211: fix slab-out-of-bounds read in ieee80211_monitor_select_queue() |
|  | CVE-2026-98802 | `8ae3f4067ba4` | mainline | seg6: ensure packet data is writable before modifying SRH and IPv6 DA |
|  | CVE-2026-98966 | `184b5ddf82d4` | mainline | bonding: fix the program leak when XDP is replaced |
|  | CVE-2026-98954 | `44378d02c5aa` | mainline | net: always dissect GSO packets in __virtio_net_hdr_to_skb() |
|  | CVE-2026-99183 | `89c2c777df17` | mainline | accel/rocket: search every core slot when looking up a scheduler |
|  | CVE-2026-100073 | `46e8e31771f4` | claude | ext4: fix transaction overflow during writeback |
|  | CVE-2026-43042 | `629ec78ef860` | claude | mpls: add seqcount to protect the platform_label{,s} pair |
|  | CVE-2026-43174 | `5d540e450895` | claude | io_uring/zcrx: fix post open error handling |
|  | CVE-2026-43326 | `415cb193bb97` | claude | sched_ext: Fix SCX_KICK_WAIT deadlock by deferring wait to balance callback |
|  | CVE-2026-46153 | `fc69decc811b` | claude | 8021q: use RCU for egress QoS mappings |
|  | CVE-2026-46153 | `7dddc74af369` | claude | 8021q: delete cleared egress QoS mappings |
|  | CVE-2026-53091 | `7fb4c1967011` | claude | net: pull headers in qdisc_pkt_len_segs_init() |
|  | CVE-2026-53106 | `350de5b8a9be` | claude | bpf: Do not allow deleting local storage in NMI |
|  | CVE-2026-63977 | `—` | claude | dpll: export __dpll_device_change_ntf() for use under dpll_lock |
|  | CVE-2026-63977 | `d733f519f644` | claude | dpll: zl3073x: use __dpll_device_change_ntf() and remove change_work |
|  | CVE-2026-64160 | `2c8f4742bb76` | claude | netfs: Fix potential for tearing in ->remote_i_size and ->zero_point |
|  | CVE-2026-68103 | `a609b6278bf3` | claude | drm/amdgpu: reject mapping a reserved doorbell to a new queue |
|  | CVE-2026-68447 | `426ffae6ecc7` | claude | drm/amdkfd: clamp v9 CRIU control stack checkpoint copy to BO size |
|  | CVE-2026-72397 | `828cd614e2af` | claude | hwmon: (pmbus/core) honor vrm_version in pmbus_data2reg_vid() |
|  | CVE-2026-74272 | `4dd86ca99ffc` | claude | cxl/region: Resolve region deletion races |
|  | CVE-2026-74314 | `a3a81d247651` | claude | bpf: Cancel special fields on map value recycle |
|  | CVE-2026-74354 | `80b89d0226a0` | claude | bpf: Take mmap_lock in zap_pages() |
|  | CVE-2026-74419 | `6e87001fe19f` | claude | accel/amdxdna: Adjust size for copy_to_user() |
|  | CVE-2026-74533 | `af24e338bf5d` | claude | Bluetooth: ISO: fix race of kfree vs kref_get_unless_zero |
|  | CVE-2026-74752 | `3dbb44d88b1e` | claude | sctp: validate cookie AUTH state before use |
|  | CVE-2026-80899 | `c37460cd9b2f` | claude | erofs: remove fscache backend entirely |
|  | CVE-2026-89584 | `14b007e17881` | claude | block: validate user space vectors during extraction |
|  | CVE-2026-89755 | `34a00895d032` | claude | mm/migrate_device: clear stale mapping after freeing swapcache |
|  | CVE-2026-89772 | `5376c9db4536` | claude | btrfs: write-protect folios during data writeback |
|  | CVE-2026-89788 | `5258572aa5fd` | claude | ksmbd: fix share_conf UAF in tree_conn disconnect |
|  | CVE-2026-89788 | `b5ec6c462aab` | claude | ksmbd: fix tree connection use-after-free in smb2_tree_connect() |
|  | CVE-2026-89805 | `df72e55e754c` | claude | drm/pagemap: Fix folio allocation fallback and use-after-put |
|  | CVE-2026-90098 | `b62793a7baee` | claude | net: sparx5: fix sleep in atomic context in MAC table access |
|  | CVE-2026-90237 | `3679da4ad8be` | claude | netfilter: nft_ct: move custom expectation support to helper |
|  | CVE-2026-90320 | `2cf82b46d5e4` | claude | ocfs2: validate external xattr entries when reading metadata |
|  | CVE-2026-93047 | `fa98563ab00d` | claude | drm/v3d: Associate BOs with every job that accesses them |
|  | CVE-2026-93135 | `9a6df65d5c6a` | claude | bpf: Introduce jit_required flag and remove bpf_prog_has_kfunc_call() |
|  | CVE-2026-93135 | `f1c27922576e` | claude | bpf: Reject programs with inlined helpers if JIT is not available |
|  | CVE-2026-93181 | `174f0582e38a` | claude | perf/x86/intel/uncore: Fix uncore_box ref/unref ordering |
|  | CVE-2026-93216 | `90f095b816e2` | claude | mm/page_owner: use memcg_data snapshot to avoid TOCTOU in print_page_owner_memcg() |
|  | CVE-2026-93270 | `7a0855e73757` | claude | bpf: Disallow interpreter fallback for BPF_ADDR_PERCPU insn |
|  | CVE-2026-97538 | `8042312e73c5` | claude | hwmon: (asus_rog_ryujin) Validate HID report lengths |
|  | CVE-2026-97563 | `5be5bdda5863` | claude | smb: client: reject out-of-bounds DataOffset in CIFSSMBRead() |
|  | CVE-2026-98106 | `c4126f1db36e` | claude | drm/pagemap: Prevent double migration of device pages |
|  | CVE-2026-98115 | `d12168084c8c` | claude | ksmbd: safely drain sessions during logoff |
|  | CVE-2026-98153 | `—` | claude | nvme: set ns->head in nvme_alloc_ns_head |
|  | CVE-2026-98153 | `56e1c6bbe4bb` | claude | nvme: fix racy access to FDP placement id array |
|  | CVE-2026-98176 | `c883d0a132d4` | claude | drm/amdkfd: Avoid integer underflow with ffs in EOP ring size calc |
|  | CVE-2026-98177 | `8ee521b8b189` | claude | drm/amdkfd: Avoid integer underflow in EOP ring size calculation. |
|  | CVE-2026-98284 | `ceac0de741bf` | claude | netlink: do not free nlk->groups while lockless readers can use it |
|  | CVE-2026-98288 | `15989abd74f1` | claude | net: stmmac: fix TSO header length truncation |
|  | CVE-2026-98318 | `23c240d9509e` | claude | smb: client: validate absolute native symlink targets before NT fixups |
|  | CVE-2026-98333 | `78183e833195` | claude | wifi: mac80211: reset the LED state when ifup fails |
|  | CVE-2026-98338 | `708f9d43d6a2` | claude | wifi: cfg80211: ibss: ref BSS entry for joined event |
|  | CVE-2026-98420 | `d7fd1f98607f` | claude | ksmbd: follow SMB2 session expiration semantics |
|  | CVE-2026-98427 | `7f4a5ec6258f` | claude | net/sched: codel: bound the dropping loop per dequeue call |
|  | CVE-2026-98431 | `a44a3f175eae` | claude | RDMA/uverbs: Fix mmap_lock/disassociation_lock circular dependency |
|  | CVE-2026-98436 | `9480dd7ec3fc` | claude | accel/amdxdna: Disable device buffer exporting |
|  | CVE-2026-98444 | `ffb48dccce19` | claude | xfs: drop dquot flush lock when we can't find a buffer to flush |
|  | CVE-2026-98449 | `8f6f8a48399f` | claude | smb: client: delete compound mids on send failure before unlock |
|  | CVE-2026-98558 | `06e3f54e8b22` | claude | net: flush skb_defer_nodes in dev_cpu_dead() |
|  | CVE-2026-98562 | `3173cba11701` | claude | net: libwx: fix races in Tx timestamp handling |
|  | CVE-2026-98589 | `a6c1edfbe240` | claude | bpf: Reject pkt arguments in mutating subprogs |
|  | CVE-2026-98599 | `79a9172f3ab4` | claude | bpf: Reject non-negative offsets in stack_slot_obj_get_spi() |
|  | CVE-2026-98617 | `b5d9e9d4d0c1` | claude | eth: fbnic: use the Rx queue napi pointer to find the napi vector |
|  | CVE-2026-98628 | `261b61d3735b` | claude | bpf: Make post-verification instruction rewrites killable |
|  | CVE-2026-98692 | `12f5d8b85a66` | claude | thunderbolt: Make the DP tunnel activation callback mandatory |
|  | CVE-2026-98714 | `e27fc915c8f5` | claude | KVM: SVM: Update control fields on #VMEXIT if and only if VMRUN succeeded |
|  | CVE-2026-98747 | `499485a67fba` | claude | serial: core: fix NULL pointer dereference in serial_core_unregister_port() |
|  | CVE-2026-98786 | `217f64f348c9` | claude | drm/amd/display: guard dc_sink dereferences in MST mode validation |
|  | CVE-2026-98788 | `f35e3b578422` | claude | futex: Fix private hash use-after-free on resize |
|  | CVE-2026-98789 | `fbd97dd1d3ce` | claude | bpf: Fix objects stuck in free_by_rcu_ttrace |
|  | CVE-2026-98799 | `17637e1a581a` | claude | bpf: Skip detached progs in trampoline images that are still in use |
|  | CVE-2026-98800 | `0fb5751a6e41` | claude | bpf: Wait for an RCU tasks grace period before freeing trampoline progs |
|  | CVE-2026-98806 | `056994563935` | claude | octeontx2-pf: Fix aura BPID assignment when CONFIG_DCB is enabled |
|  | CVE-2026-98814 | `72ece656abd4` | claude | nvme: fix command effects log lifetime for multipath heads |
|  | CVE-2026-98816 | `ad139384ecdd` | claude | bpf: Fix overflow of jump offset in constant blinding |
|  | CVE-2026-98818 | `af2fb3ee6679` | claude | mm/slab: do not wake up kswapd in __kfree_rcu_sheaf() |
|  | CVE-2026-98869 | `d977dca7d073` | claude | bpf: Extract is_addr_space_cast32() utility function |
|  | CVE-2026-98869 | `ef1ddbfcfaef` | claude | bpf: Track upper 32-bit register halves' liveness in compute_live_registers() |
|  | CVE-2026-98869 | `7ce090afbf72` | claude | bpf: Infer zext_dst based on static register liveness analysis |
|  | CVE-2026-98926 | `8fa813b7fd1e` | claude | drm/amd/display: Remove sink usage from DPMS |
|  | CVE-2026-98946 | `6abc8e4dcfbc` | claude | drm/vc4: Disable the V3D interrupt across runtime suspend |
|  | CVE-2026-98951 | `59052a88ba5f` | claude | riscv: ptrace: Zero-initialize regset buffers before copyin |
|  | CVE-2026-98960 | `51562a8cb116` | claude | btrfs: don't stash io_uring encoded data across -EAGAIN |
|  | CVE-2026-98972 | `e06b678e3b4e` | claude | cgroup/cpuset: Don't access cpuset_cgrp_subsys.root in is_in_v2_mode() |
|  | CVE-2026-99076 | `ac76cab50e89` | claude | ipv6: udp: Create exceptions before socket matching |
|  | CVE-2026-99109 | `4aa2c106aef4` | claude | smb: client: reject SetEA requests that do not fit the request buffer |
|  | CVE-2026-99172 | `7229d74e5e8c` | claude | ipc: create_ipc_ns: drop mqueue mount on sysctl setup failure |
|  | CVE-2026-99172 | `f0e48172a59e` | claude | ipc: drop the mqueue mount with kern_unmount() on setup failure |
|  | CVE-2026-98118 | `fed0b33e6c58` | claude | netfs: Fix readahead synchronisation issues by loading all folios upfront |
|  | CVE-2026-98124 | `448ba0ae65ca` | claude | smb/client: invalidate fscache for fallocate range operations |
|  | CVE-2026-98685 | `4721587f96cb` | claude | smb: client: discard post-EOF pagecache when extending a file via clone range |
|  | CVE-2026-72377 | `81e985b4c3a6` | claude | afs: Remove setting of AS_RELEASE_ALWAYS for symlinks and mountpoints |
|  | CVE-2026-80785 | `061db6b7a910` | claude | fbdev: serialize mode sysfs access with lock_fb_info() |
|  | CVE-2026-90321 | `8914a3330b72` | claude | ocfs2: validate inline xattrs during inode block validation |
|  | CVE-2026-98715 | `60d93c27859f` | claude | KVM: SVM: Preserve TLB control (i.e. pending TLB flush) on failed VMRUN |
|  | CVE-2026-98815 | `—` | claude | nvme: add nvme_get_ns_head() |
|  | CVE-2026-98815 | `9952f3882ecb` | claude | nvme: fix cdev lifetime |
|  | CVE-2026-98125 | `01261a6fa48b` | claude | smb/client: fix stale page cache in insert/collapse range |
|  | CVE-2026-98682 | `c9b1194e8ec9` | claude | smb: client: drain and invalidate before server-side copy/clone |

### Not affected (reviewed) (19)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
|  | CVE-2025-68226 | `abd29b6e17a9` | mainline | smb: client: fix incomplete backport in cfids_invalidation_worker() — stable-only fix; no cfids_invalidation_worker(), laundromat worker drops the ref |
|  | CVE-2026-52945 | `168ee1549fa2` | mainline | Revert "wireguard: device: enable threaded NAPI" — reverts a stable-only backport; mainline keeps threaded NAPI |
|  | CVE-2026-52945 | `42bc3f45425b` | mainline | Revert "wireguard: device: enable threaded NAPI" — reverts a stable-only backport; mainline keeps threaded NAPI |
|  | CVE-2026-52945 | `cfdb22762f90` | mainline | Revert "wireguard: device: enable threaded NAPI" — reverts a stable-only backport; mainline keeps threaded NAPI |
|  | CVE-2026-52945 | `e94b369ff82f` | mainline | Revert "wireguard: device: enable threaded NAPI" — reverts a stable-only backport; mainline keeps threaded NAPI |
|  | CVE-2026-23288 | `1110a949675e` | mainline | accel/amdxdna: Fix out-of-bounds memset in command slot handling — memset from 3d32eb7a5ecf not in 6.18; slot space checked first |
|  | CVE-2026-43095 | `4e53116437e9` | mainline | ASoC: SDCA: Fix errors in IRQ cleanup — 6.18 has no caller of sdca_irq_populate() |
|  | CVE-2026-80657 | `506255d46bdb` | mainline | accel/amdxdna: Guard management mailbox channel cleanup against NULL pointer — 6.18 frees the channel through the NULL-safe aie2_destroy_mgmt_chann() |
|  | CVE-2026-53243 | `6d99479799c6` | mainline | rseq: Fix using an uninitialized stack variable in rseq_exit_user_update() — rseq_entry.h and the Fixes: commit 82f572449cfe not in 6.18 |
|  | CVE-2026-72203 | `76bc14c7097f` | mainline | ntfs: skip extent mft records in writeback to prevent deadlock — fs/ntfs (classic) not in 6.18; removed in 6.9 |
|  | CVE-2026-72200 | `ec4f061f2219` | mainline | ntfs: detect mapping-pairs LCN accumulator overflow — fs/ntfs (classic) not in 6.18; removed in 6.9 |
|  | CVE-2026-74342 | `6cccc49b027c` | mainline | kernfs: link kn to its parent before the LSM init hook — needs the per-sb xattr cache 12e9e3cd03b5, not in 6.18 |
|  | CVE-2026-72198 | `097cdfd0a55d` | mainline | ntfs: reject non-resident records for resident-only attributes — fs/ntfs (classic) not in 6.18; removed in 6.9 |
|  | CVE-2026-99101 | `0ab6dc1ac460` | mainline | ntfs: move attribute payload before shrinking its record — fs/ntfs (classic) not in 6.18; removed in 6.9 |
|  | CVE-2026-89611 | `a83e82b0ec3a` | mainline | ntfs: validate non-resident attribute offsets — fs/ntfs (classic) not in 6.18; removed in 6.9 |
|  | CVE-2026-89610 | `fea9e4488f38` | mainline | ntfs: verify run length exceeding volume boundary — fs/ntfs (classic) not in 6.18; removed in 6.9 |
|  | CVE-2026-89632 | `05f78e6cf34e` | mainline | smb: client: fix use-before-check of ReparseDataLength in reparse_buf_ptr() — 6.18 checks the length before it reads it |
|  | CVE-2026-98938 | `9a7931e847f3` | mainline | rust: irq: pass RegistrationInner as cookie to request_irq — fix already in 6.18.y as 8f317daa50fe |
|  | CVE-2026-99151 | `55a67aa89342` | mainline | drm/amd/display: Fix NULL sink dereference in USB4 bandwidth functions — bug comes from 8fa813b7fd1e, not in 6.18 |

## 7.3 (base 7.3.1, `79a907609d53`)

Already in tree: 147

### Included (1)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
|  | CVE-2026-98941 | `40554d1221e3` | mainline | ext4: don't enable large folios on encrypted inodes |

### Not affected (reviewed) (7)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
|  | CVE-2025-68226 | `abd29b6e17a9` | mainline | smb: client: fix incomplete backport in cfids_invalidation_worker() — stable-only fix; no cfids_invalidation_worker(), laundromat worker drops the ref |
|  | CVE-2026-52945 | `168ee1549fa2` | mainline | Revert "wireguard: device: enable threaded NAPI" — reverts a stable-only backport; mainline keeps threaded NAPI |
|  | CVE-2026-52945 | `42bc3f45425b` | mainline | Revert "wireguard: device: enable threaded NAPI" — reverts a stable-only backport; mainline keeps threaded NAPI |
|  | CVE-2026-52945 | `cfdb22762f90` | mainline | Revert "wireguard: device: enable threaded NAPI" — reverts a stable-only backport; mainline keeps threaded NAPI |
|  | CVE-2026-52945 | `e94b369ff82f` | mainline | Revert "wireguard: device: enable threaded NAPI" — reverts a stable-only backport; mainline keeps threaded NAPI |
|  | CVE-2026-68086 | `2dfe9f5c91d0` | mainline | mm/khugepaged: write all dirty file folios when collapsing — 044925f9b565 removed the nr_thps code |
|  | CVE-2026-98938 | `9a7931e847f3` | mainline | rust: irq: pass RegistrationInner as cookie to request_irq — 98c63ce4d760 removed RegistrationInner |
