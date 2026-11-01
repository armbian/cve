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

### Not affected (reviewed) (18)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
|  | CVE-2025-68226 | `abd29b6e17a9` | mainline | smb: client: fix incomplete backport in cfids_invalidation_worker() — stable-only fix; no cfids_invalidation_worker(), laundromat worker drops the ref |
|  | CVE-2026-52945 | `168ee1549fa2` | mainline | Revert "wireguard: device: enable threaded NAPI" — reverts a stable-only backport; mainline keeps threaded NAPI |
|  | CVE-2026-52945 | `cfdb22762f90` | mainline | Revert "wireguard: device: enable threaded NAPI" — reverts a stable-only backport; mainline keeps threaded NAPI |
|  | CVE-2026-52945 | `42bc3f45425b` | mainline | Revert "wireguard: device: enable threaded NAPI" — reverts a stable-only backport; mainline keeps threaded NAPI |
|  | CVE-2026-52945 | `e94b369ff82f` | mainline | Revert "wireguard: device: enable threaded NAPI" — reverts a stable-only backport; mainline keeps threaded NAPI |
|  | CVE-2026-23288 | `1110a949675e` | mainline | accel/amdxdna: Fix out-of-bounds memset in command slot handling — memset from 3d32eb7a5ecf not in 6.18; slot space checked first |
|  | CVE-2026-43095 | `4e53116437e9` | mainline | ASoC: SDCA: Fix errors in IRQ cleanup — 6.18 has no caller of sdca_irq_populate() |
|  | CVE-2026-80657 | `506255d46bdb` | mainline | accel/amdxdna: Guard management mailbox channel cleanup against NULL pointer — 6.18 frees the channel through the NULL-safe aie2_destroy_mgmt_chann() |
|  | CVE-2026-53243 | `6d99479799c6` | mainline | rseq: Fix using an uninitialized stack variable in rseq_exit_user_update() — rseq_entry.h and the Fixes: commit 82f572449cfe not in 6.18 |
|  | CVE-2026-72203 | `76bc14c7097f` | mainline | ntfs: skip extent mft records in writeback to prevent deadlock — fs/ntfs (classic) not in 6.18; removed in 6.9 |
|  | CVE-2026-72200 | `ec4f061f2219` | mainline | ntfs: detect mapping-pairs LCN accumulator overflow — fs/ntfs (classic) not in 6.18; removed in 6.9 |
|  | CVE-2026-74342 | `6cccc49b027c` | mainline | kernfs: link kn to its parent before the LSM init hook — needs the per-sb xattr cache 12e9e3cd03b5, not in 6.18 |
|  | CVE-2026-72198 | `097cdfd0a55d` | mainline | ntfs: reject non-resident records for resident-only attributes — fs/ntfs (classic) not in 6.18; removed in 6.9 |
|  | CVE-2026-89611 | `a83e82b0ec3a` | mainline | ntfs: validate non-resident attribute offsets — fs/ntfs (classic) not in 6.18; removed in 6.9 |
|  | CVE-2026-89610 | `fea9e4488f38` | mainline | ntfs: verify run length exceeding volume boundary — fs/ntfs (classic) not in 6.18; removed in 6.9 |
|  | CVE-2026-89632 | `05f78e6cf34e` | mainline | smb: client: fix use-before-check of ReparseDataLength in reparse_buf_ptr() — 6.18 checks the length before it reads it |
|  | CVE-2026-98938 | `9a7931e847f3` | mainline | rust: irq: pass RegistrationInner as cookie to request_irq — fix already in 6.18.y as 8f317daa50fe |
|  | CVE-2026-99151 | `55a67aa89342` | mainline | drm/amd/display: Fix NULL sink dereference in USB4 bandwidth functions — bug comes from 8fa813b7fd1e, not in 6.18 |

## 6.12 (base 6.12.115, `03bae623ec32`)

Already in tree: 131 · Other architectures (not built): 12

### Included (172)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
|  | CVE-2026-98466 | `3a8c562892b9` | stable-queue | KVM: arm64: Transfer the hyp stack pages out of the host stage-2 |
|  | CVE-2026-98853 | `006c8b834aed` | stable-queue | net: gso: limit recursive IP-in-IP segmentation |
|  | CVE-2026-92499 | `bc4b7b0414c3` | stable-queue | ext4: validate readdir offset before accessing dirent |
|  | CVE-2026-98439 | `4fd5bad647bf` | stable-queue | smb/server: cancel async requests when closing connection |
|  | CVE-2025-71302 | `efe24898485c` | mainline | drm/panthor: fix for dma-fence safe access rules |
|  | CVE-2026-43369 | `062ea905fff7` | mainline | drm/amd: Fix NULL pointer dereference in device cleanup |
|  | CVE-2026-98376 | `593980175389` | mainline | bpf: Use array_map_meta_equal for percpu array inner map replacement |
|  | CVE-2026-90306 | `8ed9bff906cf` | mainline | ARM: 9481/2: breakpoint: CFI breakpoints only on demand |
|  | CVE-2026-80579 | `95e647d2a530` | mainline | fbdev: clear fb_info->mode before deleting a videomode |
|  | CVE-2026-80580 | `d15d51fb26e8` | mainline | fbdev: bound mode sysfs output to the sysfs buffer |
|  | CVE-2026-98364 | `9fa903b24b1f` | mainline | xfrm: hold net_device reference under RCU in bundle creation |
|  | CVE-2026-98355 | `99c24a8968eb` | mainline | RDMA/rtrs: guard against null kobj name |
|  | CVE-2026-99087 | `7d4d4f3b668d` | mainline | dm-integrity: fix NULL pointer dereference when the 'R' flag is used |
|  | CVE-2026-98834 | `26300879cd8e` | mainline | mtd: core: avoid double-free of OTP NVMEM device |
|  | CVE-2026-98393 | `b83641e0ab8b` | mainline | net: ipv4: Fix UDP length overflow with PMTU discover and big MTU |
|  | CVE-2026-98332 | `6f0a100df853` | mainline | wifi: mac80211: only operate on TDLS peers in the TDLS code |
|  | CVE-2026-98321 | `cbdd39ce4253` | mainline | netfilter: nf_nat: unregister and release hooks on error |
|  | CVE-2026-98292 | `8879e3e0a84a` | mainline | Bluetooth: btmtksdio, btmtkuart: validate WMT event length before struct access |
|  | CVE-2026-98285 | `2842ce397dd0` | mainline | net: bridge: vlan: fix bugs caused by switchdev deletion errors |
|  | CVE-2026-98824 | `6bdcdb31318c` | mainline | wifi: mac80211: validate TX status rate metadata |
|  | CVE-2026-98740 | `b62a264163ca` | mainline | EDAC/altera: Drop __init from ECC setup paths for re-probe safety |
|  | CVE-2026-98932 | `eef3b67f9c67` | mainline | EDAC/altera: Fix use-after-free in error paths |
|  | CVE-2026-98810 | `6f63e919fe1e` | mainline | wifi: mac80211: fix slab-out-of-bounds read in ieee80211_monitor_select_queue() |
|  | CVE-2026-98802 | `8ae3f4067ba4` | mainline | seg6: ensure packet data is writable before modifying SRH and IPv6 DA |
|  | CVE-2026-98966 | `184b5ddf82d4` | mainline | bonding: fix the program leak when XDP is replaced |
|  | CVE-2026-99026 | `489114c9ecae` | mainline | net: team: free skb when broadcast has no txable port |
|  | CVE-2026-46279 | `6b1842775a46` | stable-list | mm/alloc_tag: clear codetag for pages allocated before page_ext initialization |
|  | CVE-2026-52953 | `a6dea58d8625` | stable-list | iommu/vt-d: Fix oops due to out of scope access |
|  | CVE-2026-80670 | `5484b43a0ec8` | stable-list | perf tools: Use perf_env__get_cpu_topology() in machine__resolve() |
|  | CVE-2026-98924 | `7459c0218742` | stable-list | fs: avoid repeated scans in evict_inodes() |
|  | CVE-2026-99021 | `e2151c29cec7` | stable-list | regulator: of: fill in supply names in of_regulator_bulk_get_all() |
|  | CVE-2026-99122 | `ad9a7da3fa39` | stable-list | vsock/vmci: validate packet source for connected sockets |
|  | CVE-2025-40025 | `c18ecd99e0c7` | claude | f2fs: fix to do sanity check on node footer for non inode dnode |
|  | CVE-2025-71117 | `935a20d1bebf` | claude | block: Remove queue freezing from several sysfs store callbacks |
|  | CVE-2025-68304 | `79a2d4678ba9` | claude | Bluetooth: hci_core: lookup hci_conn on RX path on protocol side |
|  | CVE-2026-23102 | `d2907cbe9ea0` | claude | arm64/fpsimd: signal: Fix restoration of SVE context |
|  | CVE-2026-31537 | `34abd408c8ba` | claude | smb: server: make use of smbdirect_socket.send_io.bcredits |
|  | CVE-2026-23348 | `—` | claude | cxl: Move devm_cxl_add_nvdimm_bridge() to cxl_pmem.ko |
|  | CVE-2026-23348 | `96a1fd0d84b1` | claude | cxl: Fix race of nvdimm_bus object when creating nvdimm objects |
|  | CVE-2026-23348 | `—` | claude | cxl/acpi: Fix CXL_ACPI and CXL_PMEM Kconfig tristate mismatch |
|  | CVE-2026-23348 | `—` | claude | cxl: Adjust the startup priority of cxl_pmem to be higher than that of cxl_acpi |
|  | CVE-2026-43367 | `72ecb1dae727` | claude | drm/amd: Fix a few more NULL pointer dereference in device cleanup |
|  | CVE-2026-53106 | `350de5b8a9be` | claude | bpf: Do not allow deleting local storage in NMI |
|  | CVE-2026-31777 | `277c6960d4dd` | claude | ALSA: ctxfi: Check the error for index mapping |
|  | CVE-2026-43326 | `415cb193bb97` | claude | sched_ext: Fix SCX_KICK_WAIT deadlock by deferring wait to balance callback |
|  | CVE-2026-31692 | `7b735ef81286` | claude | rtnetlink: add missing netlink_ns_capable() check for peer netns |
|  | CVE-2026-46017 | `3bac01168982` | claude | mm: fix deferred split queue races during migration |
|  | CVE-2026-31591 | `cb923ee6a80f` | claude | KVM: SEV: Lock all vCPUs when synchronzing VMSAs for SNP launch finish |
|  | CVE-2026-23265 | `50ac3ecd8e05` | claude | f2fs: fix to do sanity check on node footer in {read,write}_end_io |
|  | CVE-2026-63858 | `10f79dbd7719` | claude | netfilter: nf_tables: add hook transactions for device deletions |
|  | CVE-2026-46153 | `fc69decc811b` | claude | 8021q: use RCU for egress QoS mappings |
|  | CVE-2026-46153 | `7dddc74af369` | claude | 8021q: delete cleared egress QoS mappings |
|  | CVE-2026-64520 | `—` | claude | firmware: arm_ffa: Fix big-endian support in __ffa_partition_info_regs_get() |
|  | CVE-2026-64520 | `3974ea193840` | claude | firmware: arm_ffa: Bound PARTITION_INFO_GET_REGS copies |
|  | CVE-2026-80872 | `—` | claude | firmware_loader: Add cancel helper for async requests |
|  | CVE-2026-80872 | `5367e2ad14f0` | claude | ALSA: hda/tas2781: Cancel async firmware request at unbind |
|  | CVE-2026-64078 | `527d6931473b` | claude | netfilter: x_tables: add and use xt_unregister_table_pre_exit |
|  | CVE-2026-64078 | `b4597d5fd7d2` | claude | netfilter: x_tables: add and use xtables_unregister_table_exit |
|  | CVE-2026-97499 | `f37bc31447c0` | claude | coresight: perf: Retrieve path and source from event data |
|  | CVE-2026-98914 | `27ef1795bc4e` | claude | drm/amdgpu: cap ATOM command table nesting depth |
|  | CVE-2026-98875 | `604d0efb17cc` | claude | drm/nouveau/gsp: add SEC2 to GA100 chip table |
|  | CVE-2026-63941 | `837263307489` | claude | KVM: arm64: Correctly cap ZCR_EL2 provided by a guest hypervisor |
|  | CVE-2026-74354 | `80b89d0226a0` | claude | bpf: Take mmap_lock in zap_pages() |
|  | CVE-2026-63805 | `4e67f504ee9d` | claude | crypto: nx - fix nx_crypto_ctx_exit argument |
|  | CVE-2026-74314 | `a3a81d247651` | claude | bpf: Cancel special fields on map value recycle |
|  | CVE-2026-72454 | `650716f23eac` | claude | i3c: mipi-i3c-hci: Fix race in i3c_hci_addr_to_dev() |
|  | CVE-2026-64160 | `2c8f4742bb76` | claude | netfs: Fix potential for tearing in ->remote_i_size and ->zero_point |
|  | CVE-2026-64066 | `8a8c0cfdf465` | claude | netfs: Fix netfs_read_to_pagecache() to pause on subreq failure |
|  | CVE-2026-64067 | `b5782e2d462c` | claude | netfs: Fix missing barriers when accessing stream->subrequests locklessly |
|  | CVE-2026-72355 | `5c6ce05e4065` | claude | netfs: Fix barriering when walking subrequest list |
|  | CVE-2026-63819 | `8712353ed80f` | claude | f2fs: fix to do sanity check on f2fs_get_node_folio_ra() |
|  | CVE-2026-93154 | `097f50384e18` | claude | RDMA/irdma: Deduplicate the irdma_del_memlist logic |
|  | CVE-2026-93154 | `a7d0a6b58256` | claude | RDMA/irdma: Add a refcount to track user ring MR associations |
|  | CVE-2026-93154 | `971e99623ed7` | claude | RDMA/irdma: Add irdma_cq fields to track pbl allocations |
|  | CVE-2026-93154 | `f67d8a08f60c` | claude | RDMA/irdma: Add refcounting to user ring MRs |
|  | CVE-2026-89722 | `dc76258d0132` | claude | PCI/sysfs: Fix out-of-bounds read in pci_write_legacy_io() |
|  | CVE-2026-93135 | `9a6df65d5c6a` | claude | bpf: Introduce jit_required flag and remove bpf_prog_has_kfunc_call() |
|  | CVE-2026-93135 | `f1c27922576e` | claude | bpf: Reject programs with inlined helpers if JIT is not available |
|  | CVE-2026-90040 | `d1a3c2162334` | claude | KVM: SEV: Forcefully invalidate SNP VMSA if its backing gmem page is zapped |
|  | CVE-2026-93099 | `2566b5cd6a27` | claude | fs/resctrl: Fix UAF from worker threads when domains are removed |
|  | CVE-2026-98926 | `8fa813b7fd1e` | claude | drm/amd/display: Remove sink usage from DPMS |
|  | CVE-2026-68382 | `—` | claude | drm/xe/migrate: Switch from drm to dev managed actions |
|  | CVE-2026-68382 | `9b7e60184f4b` | claude | drm/xe/guc: Hold device ref until queue teardown completes |
|  | CVE-2026-98815 | `—` | claude | nvme: add nvme_get_ns_head() |
|  | CVE-2026-98815 | `9952f3882ecb` | claude | nvme: fix cdev lifetime |
|  | CVE-2026-93047 | `fa98563ab00d` | claude | drm/v3d: Associate BOs with every job that accesses them |
|  | CVE-2026-92518 | `52fb1756ea1d` | claude | riscv, bpf: Fix kernel stack corruption in tailcall with CFI |
|  | CVE-2026-92500 | `7edbb323bab2` | claude | ext4: use fsdata to track inline data write state and fix race |
|  | CVE-2026-92493 | `8d31bb145164` | claude | cpufreq: amd-pstate-ut: Skip tests when amd-pstate driver is not active |
|  | CVE-2026-74560 | `a3c8382ebce4` | claude | xsk: fix buffer leak in xsk_drop_skb() for AF_XDP multi-buffer Tx |
|  | CVE-2026-90379 | `915672c5ae32` | claude | wifi: mt76: mt7921: Add PCIe AER handler support to prevent system crash |
|  | CVE-2026-93276 | `49c9b71b4508` | claude | phy: renesas: phy-rcar-gen3-usb2: Fix devm action registration for disabled VBUS regulator |
|  | CVE-2026-90261 | `ecc05eda9a34` | claude | btrfs: zoned: flush active metadata block group at btree_writepages() start |
|  | CVE-2026-89935 | `d378fceaafd7` | claude | iio: light: apds9306: fix PM reference leak in apds9306_read_data() |
|  | CVE-2026-80785 | `061db6b7a910` | claude | fbdev: serialize mode sysfs access with lock_fb_info() |
|  | CVE-2026-89637 | `730d0bb19507` | claude | smb: client: fix UAF and buffer leak in cifs_check_trans2() for malformed secondary T2 |
|  | CVE-2026-81010 | `14572de82e50` | claude | io_uring/waitid: honor task_work cancellation |
|  | CVE-2026-98125 | `01261a6fa48b` | claude | smb/client: fix stale page cache in insert/collapse range |
|  | CVE-2026-98674 | `549b71ce0506` | claude | iio: adc: adi-axi-adc: Initialize state mutex |
|  | CVE-2026-90317 | `180c7000712d` | claude | bpf: Invalidate RCU pointers after final spin unlock |
|  | CVE-2026-90315 | `747b9bbbbdfd` | claude | PCI/sysfs: Add lockdown checks to legacy I/O and memory handlers |
|  | CVE-2026-93044 | `34746b5a84ec` | claude | bpf: Disallow interpreter fallback for arena-related insns |
|  | CVE-2026-93270 | `7a0855e73757` | claude | bpf: Disallow interpreter fallback for BPF_ADDR_PERCPU insn |
|  | CVE-2026-98115 | `d12168084c8c` | claude | ksmbd: safely drain sessions during logoff |
|  | CVE-2026-99076 | `ac76cab50e89` | claude | ipv6: udp: Create exceptions before socket matching |
|  | CVE-2026-98087 | `dae5c0292080` | claude | sched/rt,dl: Skip migrate-disabled tasks when picking a push candidate |
|  | CVE-2026-98353 | `00baeade709f` | claude | RDMA/erdma: Use IRQ-safe XArray helpers for QP and CQ tables |
|  | CVE-2026-97565 | `e6142a8bfc23` | claude | smb: client: reject short READ responses in CIFSSMBRead() |
|  | CVE-2026-98341 | `dab68a74e90b` | claude | wifi: cfg80211: don't free driver-owned scan requests |
|  | CVE-2026-98338 | `708f9d43d6a2` | claude | wifi: cfg80211: ibss: ref BSS entry for joined event |
|  | CVE-2026-98333 | `78183e833195` | claude | wifi: mac80211: reset the LED state when ifup fails |
|  | CVE-2026-98330 | `4635b1a1c1d6` | claude | wifi: cfg80211: get the wiphy out of a dying network namespace |
|  | CVE-2026-98180 | `01c8d1f385f7` | claude | drm/msm: RCU-free the scheduler-containing ring and VM objects |
|  | CVE-2026-98317 | `6d79b223ec44` | claude | neighbour: Enforce min/max to NDTPA_INTERVAL_PROBE_TIME_MS. |
|  | CVE-2026-98313 | `e249a6e2a130` | claude | drm/msm/dp: skip PUSH_IDLE when the link was never enabled |
|  | CVE-2026-98304 | `23ca4ddc4fce` | claude | net: bcmgenet: restore the hardware filters on open |
|  | CVE-2026-98294 | `4e93c65f8782` | claude | Bluetooth: hci_qca: Do not write to the serial port after it is closed |
|  | CVE-2026-98289 | `4a4263dfeaba` | claude | af_unix: Unify scc_index when finalising SCC in __unix_walk_scc(). |
|  | CVE-2026-98288 | `15989abd74f1` | claude | net: stmmac: fix TSO header length truncation |
|  | CVE-2026-98286 | `c391a40f7188` | claude | drop_monitor: use timer_shutdown_sync() to prevent timer rearming during teardown |
|  | CVE-2026-98284 | `ceac0de741bf` | claude | netlink: do not free nlk->groups while lockless readers can use it |
|  | CVE-2026-98279 | `76bf149cd029` | claude | btrfs: handle lack of space when cleaning up verity items |
|  | CVE-2026-98427 | `7f4a5ec6258f` | claude | net/sched: codel: bound the dropping loop per dequeue call |
|  | CVE-2026-98277 | `490599ab2313` | claude | eth: fbnic: ring the doorbell if a burst ends in a drop |
|  | CVE-2026-98408 | `6274281c41ef` | claude | watchdog: rzv2h: Avoid division by zero |
|  | CVE-2026-98273 | `a5f7a5bb3b7f` | claude | x86/kprobes: Fix crash when probing CS CALL instructions |
|  | CVE-2026-98176 | `c883d0a132d4` | claude | drm/amdkfd: Avoid integer underflow with ffs in EOP ring size calc |
|  | CVE-2026-98177 | `8ee521b8b189` | claude | drm/amdkfd: Avoid integer underflow in EOP ring size calculation. |
|  | CVE-2026-98628 | `261b61d3735b` | claude | bpf: Make post-verification instruction rewrites killable |
|  | CVE-2026-98449 | `8f6f8a48399f` | claude | smb: client: delete compound mids on send failure before unlock |
|  | CVE-2026-98829 | `5e4f3509793b` | claude | wifi: mac80211: drop oversized fragments to avoid extra_len overflow |
|  | CVE-2026-98599 | `79a9172f3ab4` | claude | bpf: Reject non-negative offsets in stack_slot_obj_get_spi() |
|  | CVE-2026-98598 | `0346ec2f080b` | claude | ipv6: Prevent rt6_insert_exception() for dying fib6_info. |
|  | CVE-2026-98863 | `10180a277549` | claude | KVM: x86: Re-pend GET_NESTED_STATE_PAGES if getting said pages fails |
|  | CVE-2026-98589 | `a6c1edfbe240` | claude | bpf: Reject pkt arguments in mutating subprogs |
|  | CVE-2026-99109 | `4aa2c106aef4` | claude | smb: client: reject SetEA requests that do not fit the request buffer |
|  | CVE-2026-98420 | `d7fd1f98607f` | claude | ksmbd: follow SMB2 session expiration semantics |
|  | CVE-2026-98424 | `a41bd1938a9b` | claude | wifi: cfg80211: undo netns switch if renaming the wiphy fails |
|  | CVE-2026-98747 | `499485a67fba` | claude | serial: core: fix NULL pointer dereference in serial_core_unregister_port() |
|  | CVE-2026-98820 | `ab6c756f28c7` | claude | blk-mq: set RQF_USE_SCHED when the operation is known |
|  | CVE-2026-98929 | `c2de369c5c5b` | claude | macsec: initialize SecY before registering the netdevice |
|  | CVE-2026-98558 | `06e3f54e8b22` | claude | net: flush skb_defer_nodes in dev_cpu_dead() |
|  | CVE-2026-98556 | `296c83b5ccc8` | claude | gve: DQO: reject TSO packets with an out of range MSS |
|  | CVE-2026-98816 | `ad139384ecdd` | claude | bpf: Fix overflow of jump offset in constant blinding |
|  | CVE-2026-98814 | `72ece656abd4` | claude | nvme: fix command effects log lifetime for multipath heads |
|  | CVE-2026-98471 | `93de2a6a4b91` | claude | KVM: SEV: Do cache maintenance on the source VM during intra-host migration |
|  | CVE-2026-98714 | `e27fc915c8f5` | claude | KVM: SVM: Update control fields on #VMEXIT if and only if VMRUN succeeded |
|  | CVE-2026-98803 | `88095728511e` | claude | net: stmmac: fix rx Scatter-Gather support |
|  | CVE-2026-98795 | `0d2c49915bc3` | claude | net: sparx5: skip ptp deinit if init was skipped |
|  | CVE-2026-98685 | `4721587f96cb` | claude | smb: client: discard post-EOF pagecache when extending a file via clone range |
|  | CVE-2026-98684 | `aa994489bd83` | claude | smb: client: flush and commit data before querying allocated ranges |
|  | CVE-2026-98683 | `8f8d32c1044f` | claude | smb: client: flush dirty data before zeroing a range |
|  | CVE-2026-98972 | `e06b678e3b4e` | claude | cgroup/cpuset: Don't access cpuset_cgrp_subsys.root in is_in_v2_mode() |
|  | CVE-2026-98989 | `c640a01a78e4` | claude | namespace: check a recursive bind mount for mount namespace loops |
|  | CVE-2026-98789 | `fbd97dd1d3ce` | claude | bpf: Fix objects stuck in free_by_rcu_ttrace |
|  | CVE-2026-98786 | `217f64f348c9` | claude | drm/amd/display: guard dc_sink dereferences in MST mode validation |
|  | CVE-2026-98978 | `f78ddcc87224` | claude | namespace: never expire a locked mount |
|  | CVE-2026-99215 | `5b4bd13e0552` | claude | power: supply: core: prevent unregistering a power supply while a callback runs |
|  | CVE-2026-98999 | `cf238c067eaa` | claude | drm/xe: Fix stale pinned_link entry when fb-pin performs the final unpin |
|  | CVE-2026-98958 | `752770d7a58c` | claude | wifi: mt76: account non-AQL frames per peer rather than per link |
|  | CVE-2026-98954 | `44378d02c5aa` | claude | net: always dissect GSO packets in __virtio_net_hdr_to_skb() |
|  | CVE-2026-98951 | `59052a88ba5f` | claude | riscv: ptrace: Zero-initialize regset buffers before copyin |
|  | CVE-2026-98946 | `—` | claude | drm/vc4: Use devm_request_irq() for automatic cleanup |
|  | CVE-2026-98946 | `6abc8e4dcfbc` | claude | drm/vc4: Disable the V3D interrupt across runtime suspend |
|  | CVE-2026-99209 | `448e76cbdc66` | claude | drm/xe: skip eviction of a BO with no resource |
|  | CVE-2026-99208 | `fd8662823caa` | claude | drm/xe/oa: Zero OA buffer at allocation |
|  | CVE-2026-99146 | `7dedc5bb11f9` | claude | drm/i915/dmc: Add sanity check for DMC load address |
|  | CVE-2026-99172 | `f0e48172a59e` | claude | ipc: drop the mqueue mount with kern_unmount() on setup failure |
|  | CVE-2026-99189 | `38d44f78f041` | claude | gpio: mxc: fix race between chained IRQ handler install and probe completion |
|  | CVE-2026-99151 | `55a67aa89342` | claude | drm/amd/display: Fix NULL sink dereference in USB4 bandwidth functions |
|  | CVE-2026-98682 | `c9b1194e8ec9` | claude | smb: client: drain and invalidate before server-side copy/clone |
|  | CVE-2026-98715 | `60d93c27859f` | claude | KVM: SVM: Preserve TLB control (i.e. pending TLB flush) on failed VMRUN |

### Needs a backport (12)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
|  | CVE-2025-38311 | `120f28a6f314` | mainline | iavf: get rid of the crit lock |
|  | CVE-2025-40146 | `b86433721f46` | mainline | blk-mq: fix potential deadlock while nr_requests grown |
|  | CVE-2025-71315 | `02e2681ffe1a` | mainline | drm/vkms: Convert to DRM's vblank timer |
|  | CVE-2026-74337 | `89edbdfc5d03` | mainline | bpf: Fix NMI/tracepoint re-entry deadlock on lru locks |
|  | CVE-2026-80899 | `c37460cd9b2f` | mainline | erofs: remove fscache backend entirely |
|  | CVE-2026-90401 | `3fe5b7c9fb72` | mainline | md: remove REQ_NOWAIT support from raid1/10/456 |
|  | CVE-2026-90237 | `3679da4ad8be` | mainline | netfilter: nft_ct: move custom expectation support to helper |
| does not build | CVE-2026-90098 | `b62793a7baee` | mainline | net: sparx5: fix sleep in atomic context in MAC table access |
|  | CVE-2026-97563 | `5be5bdda5863` | mainline | smb: client: reject out-of-bounds DataOffset in CIFSSMBRead() |
|  | CVE-2026-98996 | `6857e209015f` | mainline | fs: don't silently unmount busy mounts |
|  | CVE-2026-98800 | `0fb5751a6e41` | mainline | bpf: Wait for an RCU tasks grace period before freeing trampoline progs |
|  | CVE-2026-98799 | `17637e1a581a` | mainline | bpf: Skip detached progs in trampoline images that are still in use |

### cve/ backport does not apply on this base (1)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
|  | CVE-2026-97563 | `5be5bdda5863` | claude | smb: client: reject out-of-bounds DataOffset in CIFSSMBRead() |

### Not affected per work package (needs review) (59)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
|  | CVE-2024-58015 | `eb8c05347138` | mainline | wifi: ath12k: Fix for out-of bound access error |
|  | CVE-2025-21752 | `dc14ba10781b` | mainline | btrfs: don't use btrfs_set_item_key_safe on RAID stripe-extents |
| does not build | CVE-2025-38036 | `13265fe7426e` | mainline | drm/xe/vf: Perform early GT MMIO initialization to read GMDID |
|  | CVE-2025-38017 | `d9ec73301099` | mainline | fs/eventpoll: fix endless busy loop after timeout has expired |
|  | CVE-2025-39762 | `158b9201c17f` | mainline | drm/amd/display: add null check |
|  | CVE-2025-38411 | `9df7b5ebead6` | mainline | netfs: Fix double put of request |
|  | CVE-2025-40217 | `3c17001b21b9` | mainline | pidfs: validate extensible ioctls |
|  | CVE-2025-40247 | `830d68f2cb8a` | mainline | drm/msm: Fix pgtable prealloc error path |
|  | CVE-2025-71202 | `e37d5a2d60a3` | mainline | iommu/sva: invalidate stale IOTLB entries for kernel address space |
|  | CVE-2026-43301 | `9cf4452e824c` | mainline | media: chips-media: wave5: Fix PM runtime usage count underflow |
|  | CVE-2026-22983 | `7d11e047eda5` | mainline | net: do not write to msg_get_inq in callee |
|  | CVE-2026-22995 | `f0d385f6689f` | mainline | ublk: fix use-after-free in ublk_partition_scan_work |
|  | CVE-2026-23117 | `42fb5f3deb58` | mainline | ice: add missing ice_deinit_hw() in devlink reinit path |
|  | CVE-2026-23152 | `1eab33aa63c9` | mainline | wifi: mac80211: correctly decode TTLM with default link map |
|  | CVE-2026-31536 | `9da82dc73cb0` | mainline | smb: server: let send_done handle a completion without IB_SEND_SIGNALED |
|  | CVE-2026-23341 | `8363c0286333` | mainline | accel/amdxdna: Fix crash when destroying a suspended hardware context |
|  | CVE-2026-23288 | `1110a949675e` | mainline | accel/amdxdna: Fix out-of-bounds memset in command slot handling |
|  | CVE-2026-31437 | `e9075e420a1e` | mainline | netfs: Fix NULL pointer dereference in netfs_unbuffered_write() on retry |
|  | CVE-2026-43070 | `a3125bc01884` | mainline | bpf: Reset register ID for BPF_END value tracking |
|  | CVE-2026-43440 | `87c2302813ab` | mainline | net/mana: Null service_wq on setup error to prevent double destroy |
|  | CVE-2026-31435 | `7e57523490cd` | mainline | netfs: Fix read abandonment during retry |
|  | CVE-2026-31742 | `40014493cece` | mainline | vt: discard stale unicode buffer on alt screen exit after resize |
|  | CVE-2026-46314 | `fb44d589bf31` | mainline | drm/v3d: Reject empty multisync extension to prevent infinite loop |
|  | CVE-2026-52994 | `1cb36e252211` | mainline | vsock/virtio: fix MSG_ZEROCOPY pinned-pages accounting |
|  | CVE-2026-46147 | `73b9c1e5da84` | mainline | KVM: arm64: Fix pin leak and publication ordering in __pkvm_init_vcpu() |
|  | CVE-2026-52966 | `dc366607c41c` | mainline | drm: Replace old pointer to new idr |
|  | CVE-2026-64212 | `d733ed481fd2` | mainline | wifi: iwlwifi: mld: don't dereference a pointer before NULL checking it |
|  | CVE-2026-64255 | `f056fc2b9274` | mainline | wifi: iwlwifi: mld: validate sta_mask before ffs() in BA session handlers |
|  | CVE-2026-63885 | `7164d78559b0` | mainline | drm/gem: fix race between change_handle and handle_delete |
|  | CVE-2026-53243 | `6d99479799c6` | mainline | rseq: Fix using an uninitialized stack variable in rseq_exit_user_update() |
|  | CVE-2026-53246 | `0861615c28de` | mainline | sctp: validate cached peer INIT chunk length in COOKIE_ECHO processing |
|  | CVE-2026-46317 | `70543358fa08` | mainline | KVM: arm64: Reassign nested_mmus array behind mmu_lock |
|  | CVE-2026-72203 | `76bc14c7097f` | mainline | ntfs: skip extent mft records in writeback to prevent deadlock |
|  | CVE-2026-72200 | `ec4f061f2219` | mainline | ntfs: detect mapping-pairs LCN accumulator overflow |
|  | CVE-2026-53145 | `1a4f03d22fb6` | mainline | drm/gem: Try to fix change_handle ioctl, attempt 4 |
|  | CVE-2026-74342 | `6cccc49b027c` | mainline | kernfs: link kn to its parent before the LSM init hook |
|  | CVE-2026-74324 | `c7369a00860a` | mainline | wifi: mt76: mt7925: validate skb length in testmode query |
|  | CVE-2026-72198 | `097cdfd0a55d` | mainline | ntfs: reject non-resident records for resident-only attributes |
|  | CVE-2026-98897 | `27a9bc968d4a` | mainline | ksmbd: don't hold ci->m_lock while waiting for a lease break ack |
| does not build | CVE-2026-72365 | `ba6a9f6533c7` | mainline | netfs: Fix writethrough to use collection offload |
|  | CVE-2026-89866 | `a52e6f7923c1` | mainline | media: chips-media: wave5: Resume device before setting EOS flag |
|  | CVE-2026-89826 | `8321b093fa6c` | mainline | drm/panthor: harden firmware build-info bounds checks |
|  | CVE-2026-74639 | `2615f0fb90df` | mainline | ALSA: us144mkii: re-anchor capture URBs on resubmission |
|  | CVE-2026-89675 | `62c0f6eaf050` | mainline | nfsd: fix UAF in async copy cancel and shutdown |
|  | CVE-2026-98162 | `39f203209671` | mainline | smb/server: fix tree connection leak in smb2_tree_connect() |
|  | CVE-2026-89611 | `a83e82b0ec3a` | mainline | ntfs: validate non-resident attribute offsets |
|  | CVE-2026-89610 | `fea9e4488f38` | mainline | ntfs: verify run length exceeding volume boundary |
|  | CVE-2026-89632 | `05f78e6cf34e` | mainline | smb: client: fix use-before-check of ReparseDataLength in reparse_buf_ptr() |
|  | CVE-2026-98119 | `8fb45a934661` | mainline | netfs: break unbuffered write when netfs_alloc_subrequest() fails |
|  | CVE-2026-98118 | `fed0b33e6c58` | mainline | netfs: Fix readahead synchronisation issues by loading all folios upfront |
|  | CVE-2026-98296 | `4b837ebd0ea2` | mainline | Bluetooth: btintel_pcie: validate TX skb length in send_sync |
|  | CVE-2026-98616 | `4bcc4a92c603` | mainline | eth: fbnic: reset num_napi when the napi vectors are freed |
|  | CVE-2026-98551 | `24b620729e53` | mainline | perf/core: Fill branch entries with a single assignment |
|  | CVE-2026-98939 | `e3ee38c1bc0b` | mainline | x86/mm: Drop unnecessary PMD page copy when freeing |
|  | CVE-2026-98719 | `8abbc76120a7` | mainline | KVM: SEV: Nullify "have run CPUs" mask pointer when freeing it |
|  | CVE-2026-98718 | `973ea70393e8` | mainline | KVM: SEV: Do cache maintenance on the source VM *before* clearing SEV state |
|  | CVE-2026-98843 | `8db55c5cd831` | mainline | netfs: zero gaps in read-gaps folio to avoid writing back stale data |
|  | CVE-2026-98839 | `39495ef5d6f8` | mainline | vt: selection: Fix unsigned underflow and slab-out-of-bounds read in paste_selection() |
|  | CVE-2026-99093 | `2fb552b0bee7` | mainline | mm: don't schedule deferred kernel page table freeing while booting |

Fix any of these with `fasttrack cve <ID>` (add `--claude` for a Claude-made backport).

## 6.1 (base 6.1.191, `08889840163e`)

Already in tree: 89 · Other architectures (not built): 18

### Included (279)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
|  | CVE-2026-98466 | `3a8c562892b9` | stable-queue | KVM: arm64: Transfer the hyp stack pages out of the host stage-2 |
|  | CVE-2026-98439 | `4fd5bad647bf` | stable-queue | smb/server: cancel async requests when closing connection |
|  | CVE-2024-26690 | `38cc3c6dcc09` | stable-queue | Revert "net: stmmac: protect updates of 64-bit statistics counters" |
|  | CVE-2024-27023 | `855678ed8534` | mainline | md: Fix missing release of 'active_io' for flush |
|  | CVE-2024-41149 | `85672ca9ceea` | mainline | block: avoid to reuse `hctx` not removed from cpuhp callback list |
|  | CVE-2026-23451 | `b7405dcf7385` | mainline | bonding: prevent potential infinite loop in bond_header_parse() |
|  | CVE-2026-93184 | `3359ba93d01a` | mainline | ASoC: fsl_audmix: rework runtime PM handling in probe |
|  | CVE-2026-80579 | `95e647d2a530` | mainline | fbdev: clear fb_info->mode before deleting a videomode |
|  | CVE-2026-98161 | `c644a2f8fef5` | mainline | nvdimm: pmem: keep PREFLUSH before data writes |
|  | CVE-2026-98364 | `9fa903b24b1f` | mainline | xfrm: hold net_device reference under RCU in bundle creation |
|  | CVE-2026-98355 | `99c24a8968eb` | mainline | RDMA/rtrs: guard against null kobj name |
|  | CVE-2026-99087 | `7d4d4f3b668d` | mainline | dm-integrity: fix NULL pointer dereference when the 'R' flag is used |
|  | CVE-2026-98058 | `d05524794240` | mainline | bpf: Mark syscall helpers as sleepable |
|  | CVE-2026-98321 | `cbdd39ce4253` | mainline | netfilter: nf_nat: unregister and release hooks on error |
|  | CVE-2026-98175 | `c65eae6f61d1` | mainline | smb: client: cancel reconnect work in clean_demultiplex_info() |
|  | CVE-2026-98292 | `8879e3e0a84a` | mainline | Bluetooth: btmtksdio, btmtkuart: validate WMT event length before struct access |
|  | CVE-2026-98285 | `2842ce397dd0` | mainline | net: bridge: vlan: fix bugs caused by switchdev deletion errors |
|  | CVE-2026-98271 | `a5117e1eccac` | mainline | net: skbuff: do not leave stale header offsets after pskb_carve() |
|  | CVE-2026-98828 | `93ce8ea70451` | mainline | wifi: ath9k: reject short WMI command responses |
|  | CVE-2026-98740 | `b62a264163ca` | mainline | EDAC/altera: Drop __init from ECC setup paths for re-probe safety |
|  | CVE-2026-98810 | `6f63e919fe1e` | mainline | wifi: mac80211: fix slab-out-of-bounds read in ieee80211_monitor_select_queue() |
|  | CVE-2026-98966 | `184b5ddf82d4` | mainline | bonding: fix the program leak when XDP is replaced |
|  | CVE-2026-98980 | `8189ab688f5a` | mainline | namei: don't reveal overmounted entries in refwalk |
|  | CVE-2026-99026 | `489114c9ecae` | mainline | net: team: free skb when broadcast has no txable port |
|  | CVE-2024-40965 | `4268254a3948` | stable-list | i2c: lpi2c: Avoid calling clk_get_rate during transfer |
|  | CVE-2026-64109 | `be309f8eae8b` | stable-list | af_unix: Fix UAF read of tail->len in unix_stream_data_wait() |
|  | CVE-2026-80670 | `5484b43a0ec8` | stable-list | perf tools: Use perf_env__get_cpu_topology() in machine__resolve() |
|  | CVE-2026-80999 | `fb58b6a696b3` | stable-list | net: dsa: realtek: use gpiod_set_value_cansleep for reset GPIO |
|  | CVE-2026-93216 | `90f095b816e2` | stable-list | mm/page_owner: use memcg_data snapshot to avoid TOCTOU in print_page_owner_memcg() |
|  | CVE-2026-97562 | `d806d5a85dcb` | stable-list | smb: client: pin DFS superblock in iterator callback |
|  | CVE-2026-97949 | `f06c2d26d199` | stable-list | configfs: unhash the dentry before dropping the item in rmdir |
|  | CVE-2026-98212 | `5d132990475f` | stable-list | mmc: hsq: Fix use-after-free in retry work |
|  | CVE-2026-99122 | `ad9a7da3fa39` | stable-list | vsock/vmci: validate packet source for connected sockets |
|  | CVE-2024-35808 | `cd32b27a66db` | claude | md/dm-raid: don't call md_reap_sync_thread() directly |
|  | CVE-2024-27079 | `81e921fd3216` | claude | iommu/vt-d: Fix NULL domain on device release |
|  | CVE-2024-26944 | `1ec17ef59168` | claude | btrfs: zoned: fix use-after-free in do_zone_finish() |
|  | CVE-2024-36949 | `d06af584be5a` | claude | amd/amdkfd: sync all devices to wait all processes being evicted |
|  | CVE-2024-42162 | `af9bcf910b1f` | claude | gve: Account for stopped queues when reading NIC stats |
|  | CVE-2024-39508 | `8a565304927f` | claude | io_uring/io-wq: Use set_bit() and test_bit() at worker->flags |
|  | CVE-2024-42317 | `d659b715e94a` | claude | mm/huge_memory: avoid PMD-size page cache if needed |
|  | CVE-2024-47703 | `5d99e198be27` | claude | bpf, lsm: Add check for BPF LSM return value |
|  | CVE-2024-47703 | `763aa759d3b2` | claude | bpf: Fix compare error in function retval_range_within |
|  | CVE-2024-47703 | `5e0b273e0a62` | claude | bpf: Reset register bounds before narrowing retval range in check_mem_access() |
|  | CVE-2024-45015 | `—` | claude | drm/msm/disp/dpu: use atomic enable/disable callbacks for encoder functions |
|  | CVE-2024-45015 | `aedf02e46eb5` | claude | drm/msm/dpu: move dpu_encoder's connector assignment to atomic_enable() |
|  | CVE-2024-47691 | `c7f114d864ac` | claude | f2fs: fix to avoid use-after-free in f2fs_stop_gc_thread() |
|  | CVE-2024-56544 | `1c0844c6184e` | claude | udmabuf: change folios array from kmalloc to kvmalloc |
|  | CVE-2024-50028 | `a42a5839f400` | claude | thermal: core: Reference count the zone in thermal_zone_get_by_id() |
|  | CVE-2024-50166 | `—` | claude | fsl/fman: Save device references taken in mac_probe() |
|  | CVE-2024-50166 | `1dec67e0d9fb` | claude | fsl/fman: Fix refcount handling of fman-related devices |
|  | CVE-2024-53219 | `41748675c0bf` | claude | virtiofs: use pages instead of pointer for kernel direct IO |
|  | CVE-2024-53079 | `f8f931bba0f9` | claude | mm/thp: fix deferred split unqueue naming and locking |
|  | CVE-2024-57809 | `—` | claude | PCI: imx6: Save and restore root port MSI control in suspend and resume |
|  | CVE-2024-57809 | `0a726f542d7c` | claude | PCI: imx6: Fix suspend/resume support on i.MX6QDL |
|  | CVE-2024-53176 | `3fa640d035e5` | claude | smb: During unmount, ensure all cached dir instances drop their dentry |
|  | CVE-2024-53176 | `—` | claude | smb: client: destroy cfid_put_wq on module exit |
|  | CVE-2024-58237 | `—` | claude | bpf: refactor bpf_helper_changes_pkt_data to use helper number |
|  | CVE-2024-58237 | `1a4607ffba35` | claude | bpf: consider that tail calls invalidate packet pointers |
|  | CVE-2024-53687 | `b3431a8bb336` | claude | riscv: Fix IPIs usage in kfence_protect_page() |
|  | CVE-2024-57857 | `16b87037b488` | claude | RDMA/siw: Remove direct link to net_device |
|  | CVE-2024-58089 | `72dad8e377af` | claude | btrfs: fix double accounting race when btrfs_run_delalloc_range() failed |
|  | CVE-2025-21817 | `7c0be4ead1f8` | claude | block: mark GFP_NOIO around sysfs ->store() |
|  | CVE-2025-21825 | `58f038e6d209` | claude | bpf: Cancel the running bpf_timer through kworker for PREEMPT_RT |
|  | CVE-2025-23133 | `—` | claude | wifi: cfg80211: call reg_notifier for self managed wiphy from driver hint |
|  | CVE-2025-23133 | `933ab187e679` | claude | wifi: ath11k: update channel list in reg notifier instead reg worker |
|  | CVE-2025-38039 | `689805dcc474` | claude | net/mlx5e: Avoid WARN_ON when configuring MQPRIO with HTB offload enabled |
|  | CVE-2025-23132 | `eb85c2410d6f` | claude | f2fs: quota: fix to avoid warning in dquot_writeback_dquots() |
|  | CVE-2025-23130 | `48ea8b200414` | claude | f2fs: fix to avoid panic once fallocation fails for pinfile |
|  | CVE-2025-22125 | `e879a0d9cb08` | claude | md/raid1,raid10: don't ignore IO flags |
|  | CVE-2025-22125 | `—` | claude | md/raid1: fix data lost for writemostly rdev |
|  | CVE-2025-22125 | `9f346f7d4ea7` | claude | md/raid1,raid10: don't handle IO error for REQ_RAHEAD and REQ_NOWAIT |
|  | CVE-2025-21976 | `—` | claude | fbdev: hyperv_fb: Simplify hvfb_putmem |
|  | CVE-2025-21976 | `ea2f45ab0e53` | claude | fbdev: hyperv_fb: Allow graceful removal of framebuffer |
|  | CVE-2025-22113 | `5a02a6204ca3` | claude | ext4: define ext4_journal_destroy wrapper |
|  | CVE-2025-22113 | `ce2f26e73783` | claude | ext4: avoid journaling sb update on error if journal is destroying |
|  | CVE-2025-37834 | `5f5ee52d4f58` | claude | mm/hwpoison: introduce folio_contain_hwpoisoned_page() helper |
|  | CVE-2025-37834 | `1b0449544c64` | claude | mm/vmscan: don't try to reclaim hwpoison folio |
|  | CVE-2025-37834 | `—` | claude | mm/vmscan: fix hwpoisoned large folio handling in shrink_folio_list |
|  | CVE-2025-38426 | `5df0d6addb7e` | claude | drm/amdgpu: Add basic validation for RAS header |
|  | CVE-2025-37776 | `d1c189c6cb8b` | claude | ksmbd: use rwsem instead of rwlock for lease break |
|  | CVE-2025-37776 | `18b4fac5ef17` | claude | ksmbd: fix use-after-free in smb_break_all_levII_oplock() |
|  | CVE-2025-37777 | `21a4e47578d4` | claude | ksmbd: fix use-after-free in __smb2_lease_break_noti() |
|  | CVE-2025-37777 | `a89f5fae998b` | claude | ksmbd: add free_transport ops in ksmbd connection |
|  | CVE-2025-37800 | `04d3e5461c1f` | claude | driver core: introduce device_set_driver() helper |
|  | CVE-2025-37800 | `18daa52418e7` | claude | driver core: fix potential NULL pointer dereference in dev_uevent() |
|  | CVE-2025-38264 | `—` | claude | llist: add interface to check if a node is on a list. |
|  | CVE-2025-38264 | `0bf04c874fcb` | claude | nvme-tcp: sanitize request list handling |
|  | CVE-2025-38207 | `2b12d06c37fd` | claude | mm: fix uprobe pte be overwritten when expanding vma |
|  | CVE-2025-39746 | `c256a94d1b1b` | claude | wifi: ath10k: shutdown driver when hardware is unreliable |
|  | CVE-2025-38449 | `5307dce878d4` | claude | drm/gem: Acquire references on GEM handles for framebuffers |
|  | CVE-2025-38449 | `f6bfc9afc751` | claude | drm/framebuffer: Acquire internal references on GEM handles |
|  | CVE-2024-57975 | `c2b47df81c8e` | claude | btrfs: do proper folio cleanup when run_delalloc_nocow() failed |
|  | CVE-2024-53218 | `7b0033dbc483` | claude | f2fs: fix race in concurrent f2fs_stop_gc_thread |
|  | CVE-2024-58098 | `51081a3f25c7` | claude | bpf: track changes_pkt_data property for global functions |
|  | CVE-2024-57795 | `2ac5415022d1` | claude | RDMA/rxe: Remove the direct link to net_device |
|  | CVE-2024-57795 | `8ce2eb9dfac8` | claude | RDMA/rxe: Fix the failure of ibv_query_device() and ibv_query_device_ex() tests |
|  | CVE-2025-39732 | `65c12b104cb9` | claude | wifi: ath11k: fix sleeping-in-atomic in ath11k_mac_op_set_bitrate_mask() |
|  | CVE-2025-39789 | `3d9eb180fbe8` | claude | crypto: x86/aegis - Add missing error checks |
|  | CVE-2025-38716 | `736a0516a162` | claude | hfs: fix general protection fault in hfs_find_init() |
|  | CVE-2025-38585 | `ee4cf798202d` | claude | staging: media: atomisp: Fix stack buffer overflow in gmin_get_var_int() |
|  | CVE-2025-39940 | `1071d560afb4` | claude | dm-stripe: fix a possible integer overflow |
|  | CVE-2025-38717 | `52565a935213` | claude | net: kcm: Fix race condition in kcm_unattach() |
|  | CVE-2025-39990 | `e4414b01c1cd` | claude | bpf: Check the helper function is valid in get_helper_proto |
|  | CVE-2025-40025 | `c18ecd99e0c7` | claude | f2fs: fix to do sanity check on node footer for non inode dnode |
|  | CVE-2025-39965 | `cd8ae32e4e46` | claude | xfrm: xfrm_alloc_spi shouldn't use 0 as SPI |
|  | CVE-2025-39927 | `15f519e9f883` | claude | ceph: fix race condition validating r_parent before applying state |
|  | CVE-2025-39947 | `6b4be64fd9fe` | claude | net/mlx5e: Harden uplink netdev access against device unbind |
|  | CVE-2025-40333 | `23361bd54966` | claude | f2fs: fix infinite loop in __insert_extent_tree() |
|  | CVE-2025-39961 | `1e56310b40fd` | claude | iommu/amd/pgtbl: Fix possible race while increase page table level |
|  | CVE-2025-40355 | `c7fbb8218b4a` | claude | sysfs: check visibility before changing group attribute ownership |
|  | CVE-2025-40303 | `2618849f31e7` | claude | btrfs: ensure no dirty metadata is written back for an fs with errors |
|  | CVE-2025-68334 | `db4a3f0fbedb` | claude | platform/x86/amd/pmc: Add support for Van Gogh SoC |
|  | CVE-2025-68296 | `eb76d0f55535` | claude | drm, fbcon, vga_switcheroo: Avoid race condition in fbcon setup |
|  | CVE-2025-71065 | `ca8b201f2854` | claude | f2fs: fix to avoid potential deadlock |
|  | CVE-2025-71160 | `—` | claude | netfilter: nf_tables: remove redundant chain validation on register store |
|  | CVE-2025-71160 | `8e1a1bc4f5a4` | claude | netfilter: nf_tables: avoid chain re-validation if possible |
|  | CVE-2025-68781 | `41ca62e3e21e` | claude | usb: phy: fsl-usb: Fix use-after-free in delayed work during device removal |
|  | CVE-2025-71272 | `1f4c9d8a1021` | claude | most: core: fix resource leak in most_register_interface error paths |
|  | CVE-2026-43172 | `58192b9ce09b` | claude | wifi: iwlwifi: fix 22000 series SMEM parsing |
|  | CVE-2026-43309 | `55dcfdf8af9c` | claude | dm raid: use proper md_ro_state enumerators |
|  | CVE-2026-43309 | `cefcb9297fbd` | claude | md raid: fix hang when stopping arrays with metadata through dm-raid |
|  | CVE-2026-31537 | `34abd408c8ba` | claude | smb: server: make use of smbdirect_socket.send_io.bcredits |
|  | CVE-2026-23239 | `e1512c1db9e8` | claude | espintcp: Fix race condition in espintcp_close() |
|  | CVE-2026-23346 | `—` | claude | mm/ioremap: define generic_ioremap_prot() and generic_iounmap() |
|  | CVE-2026-23346 | `—` | claude | mm: ioremap: allow ARCH to have its own ioremap method definition |
|  | CVE-2026-23346 | `—` | claude | arm64 : mm: add wrapper function ioremap_prot() |
|  | CVE-2026-23346 | `f6bf47ab32e0` | claude | arm64: io: Rename ioremap_prot() to __ioremap_prot() |
|  | CVE-2026-23346 | `8f098037139b` | claude | arm64: io: Extract user memory type in ioremap_prot() |
|  | CVE-2026-23346 | `bb756b11ad63` | claude | arm64: io: Reject non-user protection in ioremap_prot() |
|  | CVE-2026-23355 | `aac9b27f7c1f` | claude | ata: libata: cancel pending work after clearing deferred_qc |
|  | CVE-2026-46014 | `3700f0788da6` | claude | KVM: SVM: Add missing save/restore handling of LBR MSRs |
|  | CVE-2026-31493 | `ef3b06742c8a` | claude | RDMA/efa: Fix use of completion ctx after free |
|  | CVE-2026-23276 | `6f1a9140ecda` | claude | net: add xmit recursion limit to tunnel xmit functions |
|  | CVE-2026-23276 | `c38b8f5f791e` | claude | net: prevent NULL deref in ip[6]tunnel_xmit() |
|  | CVE-2026-23276 | `77facb35227c` | claude | net: increase IP_TUNNEL_RECURSION_LIMIT to 5 |
|  | CVE-2026-23276 | `5638504a2aa9` | claude | gtp: disable BH before calling udp_tunnel_xmit_skb() |
|  | CVE-2026-23393 | `3715a0085531` | claude | bridge: cfm: Fix race condition in peer_mep deletion |
|  | CVE-2026-43409 | `—` | claude | kprobe/ftrace: bail out if ftrace was killed |
|  | CVE-2026-43409 | `—` | claude | kprobe/ftrace: fix build error due to bad function definition |
|  | CVE-2026-43409 | `e113f0b46d19` | claude | kprobes: avoid crash when rmmod/insmod after ftrace killed |
|  | CVE-2026-46282 | `aac0a51b1670` | claude | iio: frequency: admv1013: fix NULL pointer dereference on str |
|  | CVE-2026-23035 | `4ef8512e1427` | claude | net/mlx5e: Pass netdev to mlx5e_destroy_netdev instead of priv |
|  | CVE-2026-53106 | `350de5b8a9be` | claude | bpf: Do not allow deleting local storage in NMI |
|  | CVE-2026-23265 | `50ac3ecd8e05` | claude | f2fs: fix to do sanity check on node footer in {read,write}_end_io |
|  | CVE-2026-43317 | `2c198c272f9c` | claude | most: core: fix leak on early registration failure |
|  | CVE-2026-46068 | `adb3faf2db1a` | claude | crypto: nx - fix bounce buffer leaks in nx842_crypto_{alloc,free}_ctx |
|  | CVE-2026-31444 | `48623ec358c1` | claude | ksmbd: fix use-after-free and NULL deref in smb_grant_oplock() |
|  | CVE-2026-22996 | `123eda2e5b16` | claude | net/mlx5e: Don't store mlx5e_priv in mlx5e_dev devlink priv |
|  | CVE-2026-43053 | `—` | claude | xfs: only assert new size for datafork during truncate extents |
|  | CVE-2026-43053 | `—` | claude | xfs: factor out xfs_attr3_node_entry_remove |
|  | CVE-2026-43053 | `—` | claude | xfs: factor out xfs_attr3_leaf_init |
|  | CVE-2026-43053 | `b854e1c4eff3` | claude | xfs: close crash window in attr dabtree inactivation |
|  | CVE-2026-31487 | `cb3d1049f4ea` | claude | driver core: generalize driver_override in struct device |
|  | CVE-2026-31487 | `cc34d77dd487` | claude | spi: use generic driver_override infrastructure |
|  | CVE-2026-31777 | `277c6960d4dd` | claude | ALSA: ctxfi: Check the error for index mapping |
|  | CVE-2026-23000 | `4dadc4077e3f` | claude | net/mlx5e: Fix crash on profile change rollback failure |
|  | CVE-2026-31692 | `7b735ef81286` | claude | rtnetlink: add missing netlink_ns_capable() check for peer netns |
|  | CVE-2026-31579 | `60a25ef8dacb` | claude | wireguard: device: use exit_rtnl callback instead of manual rtnl_lock in pre_exit |
|  | CVE-2026-63858 | `10f79dbd7719` | claude | netfilter: nf_tables: add hook transactions for device deletions |
|  | CVE-2026-46153 | `fc69decc811b` | claude | 8021q: use RCU for egress QoS mappings |
|  | CVE-2026-46153 | `7dddc74af369` | claude | 8021q: delete cleared egress QoS mappings |
|  | CVE-2026-98916 | `55308cee9c21` | claude | wifi: nl80211: check link is beaconing for color change |
|  | CVE-2026-64078 | `527d6931473b` | claude | netfilter: x_tables: add and use xt_unregister_table_pre_exit |
|  | CVE-2026-64078 | `b4597d5fd7d2` | claude | netfilter: x_tables: add and use xtables_unregister_table_exit |
|  | CVE-2026-43500 | `aa54b1d27fe0` | claude | rxrpc: Also unshare DATA/RESPONSE packets when paged frags are present |
|  | CVE-2026-53179 | `514ab9836459` | claude | staging: rtl8723bs: fix buffer over-read in rtw_update_protection |
|  | CVE-2026-64160 | `2c8f4742bb76` | claude | netfs: Fix potential for tearing in ->remote_i_size and ->zero_point |
|  | CVE-2026-97499 | `f37bc31447c0` | claude | coresight: perf: Retrieve path and source from event data |
|  | CVE-2026-97496 | `7ef144458f48` | claude | drm/amdkfd: Fix OOB memory exposure in get_wave_state() |
|  | CVE-2026-98914 | `27ef1795bc4e` | claude | drm/amdgpu: cap ATOM command table nesting depth |
|  | CVE-2026-53091 | `—` | claude | net: do not use skb_mac_header() in qdisc_pkt_len_init() |
|  | CVE-2026-53091 | `—` | claude | net: account for encap headers in qdisc pkt len |
|  | CVE-2026-53091 | `7fb4c1967011` | claude | net: pull headers in qdisc_pkt_len_segs_init() |
|  | CVE-2026-53091 | `28a57fb2c5df` | claude | net: iptunnel: fix stale transport header during tunnel decapsulation |
|  | CVE-2026-53091 | `fa90a3145c03` | claude | xfrm: Don't clobber inner headers when already set |
|  | CVE-2026-53115 | `6c8dfb036273` | claude | bus: fsl-mc: use generic driver_override infrastructure |
|  | CVE-2026-31527 | `813bbc4d33d2` | claude | hwmon: axi-fan: don't use driver_override as IRQ name |
|  | CVE-2026-31527 | `2b38efc05bf7` | claude | driver core: platform: use generic driver_override infrastructure |
|  | CVE-2026-53118 | `85bb534ff12a` | claude | vdpa: use generic driver_override infrastructure |
|  | CVE-2026-53117 | `ac4d8bb6e2e1` | claude | s390/cio: use generic driver_override infrastructure |
|  | CVE-2026-53120 | `10a4206a2401` | claude | PCI: use generic driver_override infrastructure |
|  | CVE-2026-64079 | `8e72510db9fa` | claude | netfilter: x_tables: allow initial table replace without emitting audit log message |
|  | CVE-2026-64079 | `b62eb8dcf2c4` | claude | netfilter: x_tables: allocate hook ops while under mutex |
|  | CVE-2026-53178 | `88e994c57a79` | claude | staging: rtl8723bs: rtw_mlme: add bounds checks before ie_length subtraction |
|  | CVE-2026-64001 | `4cc54bdd54b3` | claude | ALSA: pcm: oss: Fix setup list UAF on proc write error |
|  | CVE-2026-64241 | `950007767823` | claude | gpio: rockchip: teardown bugs and resource leaks |
|  | CVE-2026-80676 | `331d8900121a` | claude | Drivers: hv: vmbus: use generic driver_override infrastructure |
|  | CVE-2026-97424 | `e3829992dd9f` | claude | drm/amdgpu/ras: add ras_suspend callback and use it for cp_ecc_error_irq |
|  | CVE-2026-63805 | `4e67f504ee9d` | claude | crypto: nx - fix nx_crypto_ctx_exit argument |
|  | CVE-2026-98906 | `aa97f11a76e5` | claude | net: lan966x: restore RX state on reload failure |
|  | CVE-2026-72469 | `af9b65b29af3` | claude | xprtrdma: Fix ep kref imbalance on ADDR_CHANGE |
|  | CVE-2026-72454 | `650716f23eac` | claude | i3c: mipi-i3c-hci: Fix race in i3c_hci_addr_to_dev() |
|  | CVE-2026-98903 | `5ccea7eacb77` | claude | mailbox: imx: Add a channel shutdown field |
|  | CVE-2026-98904 | `1f602619e408` | claude | mailbox: imx: Use devm_pm_runtime_enable() |
|  | CVE-2026-63819 | `8712353ed80f` | claude | f2fs: fix to do sanity check on f2fs_get_node_folio_ra() |
|  | CVE-2026-98901 | `5015191096db` | claude | ksmbd: fix lease break and ack state handling |
|  | CVE-2026-64513 | `c7722e5e1dae` | claude | KVM: x86: Move update_cr8_intercept() to lapic.c |
|  | CVE-2026-64513 | `bb365a506b1e` | claude | KVM: x86: Unconditionally recompute CR8 intercept on PPR update |
|  | CVE-2026-72397 | `828cd614e2af` | claude | hwmon: (pmbus/core) honor vrm_version in pmbus_data2reg_vid() |
|  | CVE-2026-98937 | `a4573a3838ae` | claude | perf/core: Check kernel access when kernel callchains are requested |
|  | CVE-2026-93154 | `097f50384e18` | claude | RDMA/irdma: Deduplicate the irdma_del_memlist logic |
|  | CVE-2026-93154 | `a7d0a6b58256` | claude | RDMA/irdma: Add a refcount to track user ring MR associations |
|  | CVE-2026-93154 | `971e99623ed7` | claude | RDMA/irdma: Add irdma_cq fields to track pbl allocations |
|  | CVE-2026-93154 | `f67d8a08f60c` | claude | RDMA/irdma: Add refcounting to user ring MRs |
|  | CVE-2026-68470 | `57d503ce32ec` | claude | wifi: mac80211: validate extension-frame layout before RX |
|  | CVE-2026-89722 | `dc76258d0132` | claude | PCI/sysfs: Fix out-of-bounds read in pci_write_legacy_io() |
|  | CVE-2026-89929 | `32912404b4b1` | claude | KVM: nVMX: Decouple INVVPID operand checks from flushing of vpid02 |
|  | CVE-2026-89929 | `6d00e67326d8` | claude | KVM: nVM: Ensure INVVPID is emulated on the correct physical CPU |
|  | CVE-2026-93799 | `6aa77efaea9e` | claude | wifi: iwlwifi: mvm: validate sta_id in BA window status notif |
|  | CVE-2026-93091 | `8e49055d0d49` | claude | firmware: arm_scmi: Quiesce notifications before teardown |
|  | CVE-2026-98926 | `8fa813b7fd1e` | claude | drm/amd/display: Remove sink usage from DPMS |
|  | CVE-2026-98815 | `—` | claude | nvme: add nvme_get_ns_head() |
|  | CVE-2026-98815 | `9952f3882ecb` | claude | nvme: fix cdev lifetime |
|  | CVE-2026-93047 | `fa98563ab00d` | claude | drm/v3d: Associate BOs with every job that accesses them |
|  | CVE-2026-92499 | `bc4b7b0414c3` | claude | ext4: validate readdir offset before accessing dirent |
|  | CVE-2026-92500 | `7edbb323bab2` | claude | ext4: use fsdata to track inline data write state and fix race |
|  | CVE-2026-92493 | `8d31bb145164` | claude | cpufreq: amd-pstate-ut: Skip tests when amd-pstate driver is not active |
|  | CVE-2026-74536 | `ce57442a3792` | claude | Bluetooth: ISO: fix leaking sk after socket release |
|  | CVE-2026-90379 | `915672c5ae32` | claude | wifi: mt76: mt7921: Add PCIe AER handler support to prevent system crash |
|  | CVE-2026-90359 | `c48796aa6c39` | claude | bpf: Reject >8 byte return values on return-reading trampoline paths |
|  | CVE-2026-74653 | `142341547127` | claude | serial: 8250_of: clear stuck empty-FIFO RX-timeout on LPC32xx |
|  | CVE-2026-90321 | `8914a3330b72` | claude | ocfs2: validate inline xattrs during inode block validation |
|  | CVE-2026-80556 | `c125ee35a49a` | claude | mmc: atmel-mci: Fix use-after-free in atmci_remove due to race condition |
|  | CVE-2026-72324 | `—` | claude | genirq/generic_chip: Introduce irq_domain_{alloc,remove}_generic_chips() |
|  | CVE-2026-72324 | `b11c513ad943` | claude | gpio: mvebu: free generic chips on unbind |
|  | CVE-2026-90320 | `2cf82b46d5e4` | claude | ocfs2: validate external xattr entries when reading metadata |
|  | CVE-2026-90315 | `747b9bbbbdfd` | claude | PCI/sysfs: Add lockdown checks to legacy I/O and memory handlers |
|  | CVE-2026-80728 | `b96c529cd255` | claude | Revert "drm/amdgpu: fix aperture mapping leak" |
|  | CVE-2026-74753 | `fa091f46c383` | claude | perf: Reject exited events as group leaders |
|  | CVE-2026-74752 | `3dbb44d88b1e` | claude | sctp: validate cookie AUTH state before use |
|  | CVE-2026-89938 | `be61c8c62526` | claude | iio: chemical: atlas-sensor: use iio_trigger_poll_nested() to fix remove UAF |
|  | CVE-2026-80580 | `d15d51fb26e8` | claude | fbdev: bound mode sysfs output to the sysfs buffer |
|  | CVE-2026-90036 | `9026932ac8be` | claude | NFSD: Prevent client use-after-free during blocked-lock reaping |
|  | CVE-2026-93221 | `11a5fe42e181` | claude | nfsd: convert nfsd_net boolean flags to unsigned long flags word |
|  | CVE-2026-90230 | `—` | claude | nvme: Add the DHCHAP maximum HD IDs |
|  | CVE-2026-90230 | `5bb96cc21883` | claude | nvmet: fix heap out-of-bounds read in nvmet_auth_negotiate() |
|  | CVE-2026-98156 | `6a736d2f9d0c` | claude | drm/virtio: use the DMA API for resource backing on Xen |
|  | CVE-2026-100072 | `a9ba4dd2f18b` | claude | ACPI: platform: Use acpi_bus_get_primary_device() |
|  | CVE-2026-90119 | `d736eba9c453` | claude | ALSA: ice1712: Fix the card leak at probe error with the auto-cleanup |
|  | CVE-2026-98148 | `cb732d027aa1` | claude | drm/gud: validate GUD_ROTATION_0 is present in supported rotations |
|  | CVE-2026-89637 | `730d0bb19507` | claude | smb: client: fix UAF and buffer leak in cifs_check_trans2() for malformed secondary T2 |
|  | CVE-2026-98142 | `92312d333bf7` | claude | drm/cirrus-qemu: Validate BAR0 size during probe |
|  | CVE-2026-98131 | `a5d946466a95` | claude | net: stmmac: fix dma mapping leak in stmmac_tso_xmit() |
|  | CVE-2026-98126 | `88972e357507` | claude | smb/client: validate new EOF for zero range |
|  | CVE-2026-98127 | `1519dc88c87f` | claude | smb/client: validate new EOF for insert range |
|  | CVE-2026-98124 | `448ba0ae65ca` | claude | smb/client: invalidate fscache for fallocate range operations |
|  | CVE-2026-98665 | `f0ea4824deeb` | claude | iio: health: max30102: fix NULL dereference in interrupt handler |
|  | CVE-2026-97938 | `5a88f78df753` | claude | reboot: fix cad_pid use-after-free race |
|  | CVE-2026-98114 | `c61dc7b1b4a3` | claude | ksmbd: propagate DACL parsing errors |
|  | CVE-2026-99109 | `4aa2c106aef4` | claude | smb: client: reject SetEA requests that do not fit the request buffer |
|  | CVE-2026-98111 | `a086c0892969` | claude | Bluetooth: btintel: validate version TLV value lengths |
|  | CVE-2026-98107 | `56c2b5831d39` | claude | Bluetooth: L2CAP: fix out-of-bounds write in l2cap_ecred_connect |
|  | CVE-2026-98103 | `2987ee196c88` | claude | igmp: convert struct ip_sf_list to RCU |
|  | CVE-2026-98099 | `0c8f56c583c3` | claude | ipv6: mcast: use rcu_assign_pointer() for __rcu list updates |
|  | CVE-2026-99076 | `ac76cab50e89` | claude | ipv6: udp: Create exceptions before socket matching |
|  | CVE-2026-98097 | `81c600c26302` | claude | tipc: Dont send random pad bytes in RESET/ACTIVATE messages |
|  | CVE-2026-98229 | `3cf5cdecd99c` | claude | xfrm: save input state data before secpath resets |
|  | CVE-2026-89793 | `6e2b571b0a54` | claude | ublk: clear VM_MAYWRITE on read-only ublk char device mmap |
|  | CVE-2026-98087 | `dae5c0292080` | claude | sched/rt,dl: Skip migrate-disabled tasks when picking a push candidate |
|  | CVE-2026-98353 | `00baeade709f` | claude | RDMA/erdma: Use IRQ-safe XArray helpers for QP and CQ tables |
|  | CVE-2026-97565 | `e6142a8bfc23` | claude | smb: client: reject short READ responses in CIFSSMBRead() |
|  | CVE-2026-98081 | `a18a6b93a284` | claude | btrfs: zoned: finish active block group cleanup if call_zone_finish() fails |
|  | CVE-2026-98079 | `2acb9f3d1cc8` | claude | btrfs: zstd: fix lost wakeup when waiting for a workspace |
|  | CVE-2026-98073 | `debac3a20dec` | claude | net: Remove conflicting altnames for dying netns in __dev_change_net_namespace(). |
|  | CVE-2026-98056 | `4ed7f3d7d435` | claude | nvme: remove stale namespaces by NSID range during scan |
|  | CVE-2026-98041 | `e51179a4e098` | claude | bpf: Don't predict JMP32 pointer vs zero comparisons |
|  | CVE-2026-98033 | `b90c5d770dad` | claude | bpf: Preserve inner map identity in callback frames |
|  | CVE-2026-98034 | `ecdc5043794c` | claude | bpf: Mark NULL kptr stores precise |
|  | CVE-2026-98026 | `4b772869a1e5` | claude | net: bridge: mcast: properly convert mglist to rcu |
|  | CVE-2026-98021 | `1aa9e143bf51` | claude | net: reject oversized tx_queue_len at netlink parse time |
|  | CVE-2026-98019 | `1a3a10b030c9` | claude | bpf: mark a NULL call argument precise |
|  | CVE-2026-97929 | `8f5ef203abda` | claude | ALSA: usbusx2y: validate URB actual_length in interrupt callback |
|  | CVE-2026-98003 | `00a7dd64888d` | claude | iommu/amd: Do not reallocate GA log buffers on resume |
|  | CVE-2026-97992 | `62be4e3e5f5f` | claude | vhost-vdpa: protect config_ctx from being freed under the config callback |
|  | CVE-2026-97994 | `ccb1dc7c527f` | claude | vhost/vdpa: reject VRING_NUM larger than device max |
|  | CVE-2026-98101 | `c073d1b070f1` | claude | ipv6: mcast: use copy-on-write RCU updates in ip6_mc_source() |
|  | CVE-2026-98102 | `93b49239840b` | claude | ipv6: mcast: fix RCU list diversion in ip6_mc_del1_src() |
|  | CVE-2026-80785 | `061db6b7a910` | claude | fbdev: serialize mode sysfs access with lock_fb_info() |
|  | CVE-2026-98125 | `01261a6fa48b` | claude | smb/client: fix stale page cache in insert/collapse range |

### Needs a backport (178)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
|  | CVE-2024-35961 | `c6e77aa9dd82` | mainline | net/mlx5: Register devlink first under devlink lock |
|  | CVE-2024-46678 | `2aeeef906d5a` | mainline | bonding: change ipsec_lock from spin lock to mutex |
|  | CVE-2024-50211 | `c226964ec786` | mainline | udf: refactor inode_bmap() to handle error |
|  | CVE-2024-56591 | `2b0f2fc9ed62` | mainline | Bluetooth: hci_conn: Use disable_delayed_work_sync |
|  | CVE-2024-58100 | `81f6d0530ba0` | mainline | bpf: check changes_pkt_data property for extension programs |
|  | CVE-2025-21693 | `12dcb0ef5406` | mainline | mm: zswap: properly synchronize freeing resources during CPU hotunplug |
|  | CVE-2025-38333 | `bb5eb8a5b222` | mainline | f2fs: fix to bail out in get_new_segment() |
|  | CVE-2025-40146 | `b86433721f46` | mainline | blk-mq: fix potential deadlock while nr_requests grown |
|  | CVE-2025-39981 | `302a1f674c00` | mainline | Bluetooth: MGMT: Fix possible UAFs |
|  | CVE-2025-71315 | `02e2681ffe1a` | mainline | drm/vkms: Convert to DRM's vblank timer |
|  | CVE-2025-68226 | `abd29b6e17a9` | mainline | smb: client: fix incomplete backport in cfids_invalidation_worker() |
|  | CVE-2025-68768 | `006a5035b495` | mainline | inet: frags: flush pending skbs in fqdir_pre_exit() |
| does not build | CVE-2025-71225 | `2cc583653bbe` | mainline | md: suspend array while updating raid_disks via sysfs |
| does not build | CVE-2026-23240 | `7bb09315f93d` | mainline | tls: Fix race condition in tls_sw_cancel_work_tx() |
|  | CVE-2026-43362 | `d78840a6a38d` | mainline | smb: client: fix in-place encryption corruption in SMB2_write() |
|  | CVE-2026-43115 | `a6fc88b22bc8` | mainline | srcu: Use irq_work to start GP in tiny SRCU |
|  | CVE-2026-43073 | `d187a86de793` | mainline | x86-64: rename misleadingly named '__copy_user_nocache()' function |
|  | CVE-2026-46054 | `82544d36b172` | mainline | selinux: fix overlayfs mmap() and mprotect() access checks |
| does not build | CVE-2026-64112 | `9fc75b71fdd3` | mainline | rbd: eliminate a race in lock_dwork draining on unmap |
|  | CVE-2026-64026 | `d2bc90cf6c75` | mainline | rxrpc: Fix DATA decrypt vs splice() by copying data to buffer in recvmsg |
|  | CVE-2026-74374 | `811545e0926d` | mainline | md/raid1,raid10: fix error-path detection with md_cloned_bio() |
|  | CVE-2026-53185 | `732fd9f0b9c1` | mainline | zram: fix use-after-free in zram_bvec_write_partial() |
|  | CVE-2026-80636 | `35e21a4dccc5` | mainline | netfilter: conntrack: revert ct extension genid infrastructure |
|  | CVE-2026-74337 | `89edbdfc5d03` | mainline | bpf: Fix NMI/tracepoint re-entry deadlock on lru locks |
|  | CVE-2026-53226 | `1c1e0fc88d6e` | mainline | gpio: rockchip: fix generic IRQ chip leak on remove |
|  | CVE-2026-74314 | `a3a81d247651` | mainline | bpf: Cancel special fields on map value recycle |
|  | CVE-2026-74272 | `4dd86ca99ffc` | mainline | cxl/region: Resolve region deletion races |
| does not build | CVE-2026-72434 | `4a597a87e2e2` | mainline | netfilter: ipset: make sure gc is properly stopped |
| does not build | CVE-2026-89899 | `0fbd5c232702` | mainline | media: cec: disable delayed work before freeing an interrupted transmit |
|  | CVE-2026-68447 | `426ffae6ecc7` | mainline | drm/amdkfd: clamp v9 CRIU control stack checkpoint copy to BO size |
|  | CVE-2026-68086 | `2dfe9f5c91d0` | mainline | mm/khugepaged: write all dirty file folios when collapsing |
|  | CVE-2026-93099 | `2566b5cd6a27` | mainline | fs/resctrl: Fix UAF from worker threads when domains are removed |
| does not build | CVE-2026-93072 | `616dd89d81ad` | mainline | irqchip/renesas-irqc: Fix generic interrupt chip leak on remove |
|  | CVE-2026-68152 | `ea20c44935d6` | mainline | amt: fix use-after-free in AMT delayed works |
|  | CVE-2026-90227 | `b53d495c7f0d` | mainline | nvme/ioctl: check SUBMIT_IO with nvme_cmd_allowed() |
|  | CVE-2026-90401 | `3fe5b7c9fb72` | mainline | md: remove REQ_NOWAIT support from raid1/10/456 |
| does not build | CVE-2026-74725 | `ec680ea4ba1b` | mainline | enic: fix tx_hang_reset use-after-free on device removal |
|  | CVE-2026-90389 | `bace2010dd7a` | mainline | md: scope memalloc_noio to allocation critical sections |
|  | CVE-2026-90333 | `68c5c42567bc` | mainline | dm-integrity: replace forgeable discard filler with a keyed sector marker |
|  | CVE-2026-89797 | `75b1e88d3425` | mainline | power: supply: ab8500_fg: fix use-after-free on remove |
|  | CVE-2026-74592 | `b80bed5c871a` | mainline | ima: Instantiate file_truncate and path_truncate hooks |
|  | CVE-2026-74677 | `fde39b8a5217` | mainline | net: usb: ipheth: fix carrier_work UAF on disconnect |
|  | CVE-2026-89913 | `f5b8f203bfc0` | mainline | KVM: arm64: vgic-v3: take an LPI reference in vgic_v3_save_pending_tables |
|  | CVE-2026-90237 | `3679da4ad8be` | mainline | netfilter: nft_ct: move custom expectation support to helper |
|  | CVE-2026-89708 | `01c5d5f58a5d` | mainline | nfsd: RCU-protect cl_cb_session to fix use-after-free on session teardown |
|  | CVE-2026-89675 | `62c0f6eaf050` | mainline | nfsd: fix UAF in async copy cancel and shutdown |
|  | CVE-2026-93235 | `5eced87b7d19` | mainline | f2fs: fix to zero post-EOF data when extending file size |
|  | CVE-2026-80920 | `cd305ee3633a` | mainline | io_uring: defer eventfd signaling when queued from a wakeup handler |
|  | CVE-2026-90154 | `c50e628122ae` | mainline | ksmbd: scope session state changes to bound connections |
| does not build | CVE-2026-90098 | `b62793a7baee` | mainline | net: sparx5: fix sleep in atomic context in MAC table access |
| does not build | CVE-2026-97600 | `ff5891b266a7` | mainline | ieee802154: cc2520: fix FIFOP work use-after-free |
|  | CVE-2026-97563 | `5be5bdda5863` | mainline | smb: client: reject out-of-bounds DataOffset in CIFSSMBRead() |
|  | CVE-2026-98067 | `82e664cf1219` | mainline | erofs: disable LZ4 rolling decompression for now |
|  | CVE-2026-98043 | `67b529f521a6` | mainline | bpf: Don't infer non-NULL from a pointer with an unbounded offset |
|  | CVE-2026-97997 | `75d276e5bb68` | mainline | virtio_ring: fix stale descriptor flags after a failed packed add |
|  | CVE-2026-97990 | `0d195797a80b` | mainline | vdpa_sim_net: check TX pull result before RX copy |
|  | CVE-2026-97988 | `e4f4761879a2` | mainline | vhost: invalidate vring access on IOTLB transitions |
|  | CVE-2026-97989 | `fa2c25b4add5` | mainline | vduse: validate virtqueue alignment |
|  | CVE-2026-98394 | `6e5ee08eb585` | mainline | af_unix: Return immediately when manage_oob() returns NULL for 0-length buffer. |
|  | CVE-2026-97984 | `0ae10b6be49b` | mainline | net: ipv6: Fix UDP length overflow with PMTU discover and big MTU |
|  | CVE-2026-98393 | `b83641e0ab8b` | mainline | net: ipv4: Fix UDP length overflow with PMTU discover and big MTU |
|  | CVE-2026-98435 | `9868f5c077df` | mainline | EDAC/altera: Use parent device for devres in altr_portb_setup() |
|  | CVE-2026-97978 | `b8bf9bfda5f6` | mainline | eth: ice: don't dereference pointers from TP_printk() |
|  | CVE-2026-97619 | `796aa0547557` | mainline | io_uring/rw: end write accounting from ->ki_complete |
|  | CVE-2026-98254 | `b7d7914a9ae3` | mainline | swiotlb: use the adjusted address for the highmem page lookup |
|  | CVE-2026-98341 | `dab68a74e90b` | mainline | wifi: cfg80211: don't free driver-owned scan requests |
|  | CVE-2026-98338 | `708f9d43d6a2` | mainline | wifi: cfg80211: ibss: ref BSS entry for joined event |
|  | CVE-2026-98337 | `733f0fde9539` | mainline | wifi: mac80211: don't start a ROC while scanning |
|  | CVE-2026-98334 | `3f28551d0241` | mainline | wifi: mac80211: reset state when starting AP fails |
|  | CVE-2026-98333 | `78183e833195` | mainline | wifi: mac80211: reset the LED state when ifup fails |
|  | CVE-2026-98425 | `a7491b7efbd9` | mainline | wifi: mac80211: don't warn when an IBSS has no channel to scan |
|  | CVE-2026-98335 | `ac7472a24bd4` | mainline | wifi: mac80211: abort chanswitch when leaving a mesh |
|  | CVE-2026-98330 | `4635b1a1c1d6` | mainline | wifi: cfg80211: get the wiphy out of a dying network namespace |
|  | CVE-2026-98332 | `6f0a100df853` | mainline | wifi: mac80211: only operate on TDLS peers in the TDLS code |
|  | CVE-2026-98424 | `a41bd1938a9b` | mainline | wifi: cfg80211: undo netns switch if renaming the wiphy fails |
|  | CVE-2026-98329 | `e14bf37bb2b3` | mainline | wifi: mac80211: don't allow injecting frames wider than the chanctx |
|  | CVE-2026-98327 | `860134b3af77` | mainline | wifi: mac80211: mesh: reset the CSA state when leaving |
|  | CVE-2026-97965 | `be83178bfc44` | mainline | vxlan: initialize _md in vxlan_xmit_one() |
|  | CVE-2026-98539 | `1abd643f3783` | mainline | fs/ntfs3: use d_instantiate_new() in ntfs_create_inode() and murder syzbot's "WARNING in do_new_mount" saga |
|  | CVE-2026-97953 | `5e38d732ec67` | mainline | net: stmmac: fix TX descriptor availability check for TSO traffic |
|  | CVE-2026-98180 | `01c8d1f385f7` | mainline | drm/msm: RCU-free the scheduler-containing ring and VM objects |
|  | CVE-2026-98248 | `8cf2093f5372` | mainline | arm64: percpu: Fix LSE operations on {8,16}-bit types |
|  | CVE-2026-97906 | `7812d6dab069` | mainline | bootconfig: Fix integer overflow in initrd size check |
|  | CVE-2026-97918 | `92383cef6679` | mainline | tracing: Undo the registration when enabling the histogram trigger fails |
| does not build | CVE-2026-98222 | `8697c431e297` | mainline | KEYS: encrypted: fix integer overflow of datablob_len |
|  | CVE-2026-98317 | `6d79b223ec44` | mainline | neighbour: Enforce min/max to NDTPA_INTERVAL_PROBE_TIME_MS. |
|  | CVE-2026-98266 | `fd95e68df6fe` | mainline | ALSA: core: Fix potential UAF after asynchronous card release |
|  | CVE-2026-98174 | `5f270f091256` | mainline | smb: client: fix rlist race and missing initialization |
|  | CVE-2026-98313 | `e249a6e2a130` | mainline | drm/msm/dp: skip PUSH_IDLE when the link was never enabled |
|  | CVE-2026-98182 | `2b04d6556964` | mainline | wifi: mac80211: refuse to make a monitor active when it has no queue |
| does not build | CVE-2026-98309 | `073a30d75f30` | mainline | drm/vc4: Use managed KMS polling to fix UAF on unbind |
|  | CVE-2026-98307 | `820b8cff81c7` | mainline | wifi: ath11k: cleanup arsta in ath11k_mac_peer_cleanup_all() |
|  | CVE-2026-98304 | `23ca4ddc4fce` | mainline | net: bcmgenet: restore the hardware filters on open |
|  | CVE-2026-98294 | `4e93c65f8782` | mainline | Bluetooth: hci_qca: Do not write to the serial port after it is closed |
|  | CVE-2026-98288 | `15989abd74f1` | mainline | net: stmmac: fix TSO header length truncation |
|  | CVE-2026-98286 | `c391a40f7188` | mainline | drop_monitor: use timer_shutdown_sync() to prevent timer rearming during teardown |
|  | CVE-2026-98284 | `ceac0de741bf` | mainline | netlink: do not free nlk->groups while lockless readers can use it |
|  | CVE-2026-98279 | `76bf149cd029` | mainline | btrfs: handle lack of space when cleaning up verity items |
|  | CVE-2026-98634 | `b6ec0f797459` | mainline | scsi: sd_zbc: Reject disks with too many zones |
|  | CVE-2026-98427 | `7f4a5ec6258f` | mainline | net/sched: codel: bound the dropping loop per dequeue call |
|  | CVE-2026-98273 | `a5f7a5bb3b7f` | mainline | x86/kprobes: Fix crash when probing CS CALL instructions |
|  | CVE-2026-98924 | `7459c0218742` | mainline | fs: avoid repeated scans in evict_inodes() |
|  | CVE-2026-98176 | `c883d0a132d4` | mainline | drm/amdkfd: Avoid integer underflow with ffs in EOP ring size calc |
|  | CVE-2026-98177 | `8ee521b8b189` | mainline | drm/amdkfd: Avoid integer underflow in EOP ring size calculation. |
|  | CVE-2026-98179 | `5155002b03b2` | mainline | drm/amdgpu: fix rmmio iounmap skipped on device removal |
|  | CVE-2026-98269 | `97fcd34aa9fd` | mainline | btrfs: abort transaction on failure to update inode for hole punching and reflinking |
|  | CVE-2026-98628 | `261b61d3735b` | mainline | bpf: Make post-verification instruction rewrites killable |
|  | CVE-2026-98506 | `a363c62a653c` | mainline | mm/hugetlb: do not dissolve gigantic pages without runtime support |
|  | CVE-2026-98505 | `39c0ceedd545` | mainline | mm/damon/vaddr: avoid hw-driven pte updates during damon_hugetlb_mkold() |
|  | CVE-2026-98620 | `310d1ac61a4d` | mainline | net: ethernet: mtk_eth_soc: unregister net_devices in case of probe failure |
| does not build | CVE-2026-98449 | `8f6f8a48399f` | mainline | smb: client: delete compound mids on send failure before unlock |
|  | CVE-2026-98509 | `b74aad23d99b` | mainline | drm/virtio: fix memory leak of fence event on execbuffer failure |
|  | CVE-2026-98829 | `5e4f3509793b` | mainline | wifi: mac80211: drop oversized fragments to avoid extra_len overflow |
|  | CVE-2026-98827 | `aeaca27c1db3` | mainline | wifi: ath9k_htc: bound TX aggregation to MAX_TX_BUF_SIZE |
|  | CVE-2026-98826 | `fcf0b58e976e` | mainline | rtc: ac100: Fix clock provider use-after-free on probe failure |
|  | CVE-2026-98598 | `0346ec2f080b` | mainline | ipv6: Prevent rt6_insert_exception() for dying fib6_info. |
|  | CVE-2026-98452 | `d2ff5fb93ea8` | mainline | smb: client: clean up failed cached directory opens |
|  | CVE-2026-98824 | `6bdcdb31318c` | mainline | wifi: mac80211: validate TX status rate metadata |
|  | CVE-2026-98822 | `7f93ca31f7fd` | mainline | wifi: mac80211: prevent AP VLAN tx from other interfaces |
|  | CVE-2026-98863 | `10180a277549` | mainline | KVM: x86: Re-pend GET_NESTED_STATE_PAGES if getting said pages fails |
|  | CVE-2026-98589 | `a6c1edfbe240` | mainline | bpf: Reject pkt arguments in mutating subprogs |
|  | CVE-2026-98503 | `951840561386` | mainline | packet: use ubuf_info completion for TX_RING packets |
|  | CVE-2026-98551 | `24b620729e53` | mainline | perf/core: Fill branch entries with a single assignment |
|  | CVE-2026-98820 | `ab6c756f28c7` | mainline | blk-mq: set RQF_USE_SCHED when the operation is known |
|  | CVE-2026-98859 | `5acb2dace582` | mainline | HID: multitouch: stop the release timer from being rearmed on remove |
|  | CVE-2026-98929 | `c2de369c5c5b` | mainline | macsec: initialize SecY before registering the netdevice |
|  | CVE-2026-98565 | `c2cdef41e0b4` | mainline | net: dsa: mt7530: fix NULL dereference on unbind of MT7531 and MT7621 |
|  | CVE-2026-98525 | `26cc0e69cce0` | mainline | mctp: route: iterate socket tag list in mctp_lookup_prealloc_tag() |
|  | CVE-2026-98558 | `06e3f54e8b22` | mainline | net: flush skb_defer_nodes in dev_cpu_dead() |
|  | CVE-2026-98556 | `296c83b5ccc8` | mainline | gve: DQO: reject TSO packets with an out of range MSS |
|  | CVE-2026-98816 | `ad139384ecdd` | mainline | bpf: Fix overflow of jump offset in constant blinding |
|  | CVE-2026-98814 | `72ece656abd4` | mainline | nvme: fix command effects log lifetime for multipath heads |
|  | CVE-2026-98996 | `6857e209015f` | mainline | fs: don't silently unmount busy mounts |
|  | CVE-2026-98932 | `eef3b67f9c67` | mainline | EDAC/altera: Fix use-after-free in error paths |
|  | CVE-2026-98471 | `93de2a6a4b91` | mainline | KVM: SEV: Do cache maintenance on the source VM during intra-host migration |
|  | CVE-2026-98715 | `60d93c27859f` | mainline | KVM: SVM: Preserve TLB control (i.e. pending TLB flush) on failed VMRUN |
|  | CVE-2026-98714 | `e27fc915c8f5` | mainline | KVM: SVM: Update control fields on #VMEXIT if and only if VMRUN succeeded |
|  | CVE-2026-98720 | `2abb25273c82` | mainline | KVM: nVMX: Force MSR bitmap refresh if runtime eVMCS controls are modified |
|  | CVE-2026-98738 | `81a2345f1984` | mainline | Bluetooth: Serialize SMP remote OOB data access |
|  | CVE-2026-98734 | `848a7a91c7f0` | mainline | Bluetooth: hci_core: Serialize SCO and ISO scheduling with teardown |
|  | CVE-2026-98737 | `8ed67535fdff` | mainline | Bluetooth: hci_sync: Fix inquiry cache use-after-free |
|  | CVE-2026-98939 | `e3ee38c1bc0b` | mainline | x86/mm: Drop unnecessary PMD page copy when freeing |
|  | CVE-2026-98719 | `8abbc76120a7` | mainline | KVM: SEV: Nullify "have run CPUs" mask pointer when freeing it |
|  | CVE-2026-98718 | `973ea70393e8` | mainline | KVM: SEV: Do cache maintenance on the source VM *before* clearing SEV state |
|  | CVE-2026-98808 | `eb7b84af0ec5` | mainline | net: systemport: Fix buffer overflow in bcm_sysport_get_stats() |
|  | CVE-2026-98807 | `04c824940d52` | mainline | net/mlx5: Fix slab-out-of-bounds when handling team device events |
|  | CVE-2026-98803 | `88095728511e` | mainline | net: stmmac: fix rx Scatter-Gather support |
|  | CVE-2026-98802 | `8ae3f4067ba4` | mainline | seg6: ensure packet data is writable before modifying SRH and IPv6 DA |
|  | CVE-2026-98801 | `37e02c42a00b` | mainline | net: restrict SO_RESERVE_MEM to TCP sockets and cap max value |
|  | CVE-2026-98800 | `0fb5751a6e41` | mainline | bpf: Wait for an RCU tasks grace period before freeing trampoline progs |
|  | CVE-2026-98799 | `17637e1a581a` | mainline | bpf: Skip detached progs in trampoline images that are still in use |
|  | CVE-2026-98853 | `006c8b834aed` | mainline | net: gso: limit recursive IP-in-IP segmentation |
|  | CVE-2026-98797 | `ea4d4b5dddb5` | mainline | net: cap skb->queue_mapping when the tx queue is picked |
|  | CVE-2026-98796 | `6f0c2c4f5e71` | mainline | net: ethernet: mtk_eth_soc: allocate dummy netdev sooner |
|  | CVE-2026-98795 | `0d2c49915bc3` | mainline | net: sparx5: skip ptp deinit if init was skipped |
|  | CVE-2026-98792 | `7c549fb7eecd` | mainline | netfilter: flowtable: generalize pending status bit |
|  | CVE-2026-98684 | `aa994489bd83` | mainline | smb: client: flush and commit data before querying allocated ranges |
|  | CVE-2026-98972 | `e06b678e3b4e` | mainline | cgroup/cpuset: Don't access cpuset_cgrp_subsys.root in is_in_v2_mode() |
|  | CVE-2026-98839 | `39495ef5d6f8` | mainline | vt: selection: Fix unsigned underflow and slab-out-of-bounds read in paste_selection() |
|  | CVE-2026-98989 | `c640a01a78e4` | mainline | namespace: check a recursive bind mount for mount namespace loops |
|  | CVE-2026-98789 | `fbd97dd1d3ce` | mainline | bpf: Fix objects stuck in free_by_rcu_ttrace |
|  | CVE-2026-98786 | `217f64f348c9` | mainline | drm/amd/display: guard dc_sink dereferences in MST mode validation |
|  | CVE-2026-98978 | `f78ddcc87224` | mainline | namespace: never expire a locked mount |
|  | CVE-2026-99215 | `5b4bd13e0552` | mainline | power: supply: core: prevent unregistering a power supply while a callback runs |
|  | CVE-2026-98959 | `858bee1c7785` | mainline | btrfs: fix xattr replace when multiple xattrs are packed in the same item |
|  | CVE-2026-98957 | `916c484d29d8` | mainline | wifi: mt76: mt7915: disable rx napi when removing device |
|  | CVE-2026-98954 | `44378d02c5aa` | mainline | net: always dissect GSO packets in __virtio_net_hdr_to_skb() |
|  | CVE-2026-99093 | `2fb552b0bee7` | mainline | mm: don't schedule deferred kernel page table freeing while booting |
|  | CVE-2026-99090 | `1a6023edfbb5` | mainline | drm/amdgpu: serialize vblank counter reads against GPU reset |
|  | CVE-2026-98947 | `7c24a4e87e21` | mainline | vsock: Fix memory leak in vmci_transport_recv_dgram_cb() |
|  | CVE-2026-98946 | `6abc8e4dcfbc` | mainline | drm/vc4: Disable the V3D interrupt across runtime suspend |
|  | CVE-2026-98975 | `d84d6c1a7f1e` | mainline | xfs: stop exchanging reflink flags when exchanging mappings |
|  | CVE-2026-99211 | `8bf659bd54e1` | mainline | netlink: reset skb headers before unicast and multicast filtering |
|  | CVE-2026-99178 | `81d99abe2bd8` | mainline | x86/kvm: Don't consume async #PF flags on a kernel #PF in NMI context |
|  | CVE-2026-99146 | `7dedc5bb11f9` | mainline | drm/i915/dmc: Add sanity check for DMC load address |
|  | CVE-2026-99172 | `f0e48172a59e` | mainline | ipc: drop the mqueue mount with kern_unmount() on setup failure |
| does not build | CVE-2026-99191 | `8070ed578b6b` | mainline | calipso: keep BIG TCP payload_len in calipso_skbuff_setattr() |
|  | CVE-2026-99151 | `55a67aa89342` | mainline | drm/amd/display: Fix NULL sink dereference in USB4 bandwidth functions |

### cve/ backport does not apply on this base (2)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
| does not build | CVE-2026-53226 | `1c1e0fc88d6e` | claude | gpio: rockchip: fix generic IRQ chip leak on remove |
|  | CVE-2026-97563 | `5be5bdda5863` | claude | smb: client: reject out-of-bounds DataOffset in CIFSSMBRead() |

### Not affected per work package (needs review) (144)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
|  | CVE-2024-26672 | `4f32504a2f85` | mainline | drm/amdgpu: Fix variable 'mca_funcs' dereferenced before NULL check in 'amdgpu_mca_smu_get_mca_entry()' |
| does not build | CVE-2024-35931 | `601429cca96b` | mainline | drm/amdgpu: Skip do PCI error slot reset during RAS recovery |
|  | CVE-2024-26691 | `10c02aad111d` | mainline | KVM: arm64: Fix circular locking dependency |
|  | CVE-2024-26914 | `39079fe8e660` | mainline | drm/amd/display: fix incorrect mpc_combine array size |
|  | CVE-2024-26913 | `faf51b201bc4` | mainline | drm/amd/display: Fix dcn35 8k30 Underflow/Corruption Issue |
|  | CVE-2024-36024 | `6226a5aa7737` | mainline | drm/amd/display: Disable idle reallow as part of command/gpint execution |
|  | CVE-2024-26758 | `1baae052cccd` | mainline | md: Don't ignore suspended array in md_check_recovery() |
|  | CVE-2024-26757 | `55a48ad2db64` | mainline | md: Don't ignore read-only array in md_check_recovery() |
|  | CVE-2024-26756 | `ad39c08186f8` | mainline | md: Don't register sync_thread for reshape directly |
|  | CVE-2024-26836 | `6f7d0f5fd8e4` | mainline | platform/x86: think-lmi: Fix password opcode ordering for workstations |
|  | CVE-2024-27411 | `f6ecfdad359a` | mainline | drm/nouveau: keep DMA buffers required for suspend/resume |
|  | CVE-2024-35843 | `def054b01a86` | mainline | iommu/vt-d: Use device rbtree in iopf reporting path |
|  | CVE-2024-35794 | `16c4770c75b1` | mainline | dm-raid: really frozen sync_thread during suspend |
|  | CVE-2024-36951 | `0cac183b98d8` | mainline | drm/amdkfd: range check cp bad op exception interrupts |
|  | CVE-2024-35957 | `89436f4f5412` | mainline | iommu/vt-d: Fix WARN_ON in iommu probe path |
|  | CVE-2024-40969 | `3bdb7f161697` | mainline | f2fs: don't set RO when shutting down f2fs |
|  | CVE-2024-36002 | `38d7b94e81d0` | mainline | dpll: fix dpll_pin_on_pin_register() for multiple parent pins |
|  | CVE-2024-42118 | `3ac31c9a707d` | mainline | drm/amd/display: Do not return negative stream id for array |
|  | CVE-2024-36887 | `387f295cb215` | mainline | e1000e: change usleep_range to udelay in PHY mdic access |
|  | CVE-2024-46729 | `3941a3aa4b65` | mainline | drm/amd/display: Fix incorrect size calculation for loop |
|  | CVE-2024-46727 | `871cd9d881fa` | mainline | drm/amd/display: Add otg_master NULL check within resource_log_pipe_topology_update |
|  | CVE-2024-46806 | `1a00f2ac82d6` | mainline | drm/amdgpu: Fix the warning division or modulo by zero |
|  | CVE-2024-47662 | `466423c6dd8a` | mainline | drm/amd/display: Remove register from DCN35 DMCUB diagnostic collection |
|  | CVE-2024-46870 | `7c70e60fbf4b` | mainline | drm/amd/display: Disable DMCUB timeout for DCN35 |
|  | CVE-2024-43901 | `5af757124792` | mainline | drm/amd/display: Fix NULL pointer dereference for DTN log in DCN401 |
|  | CVE-2024-46776 | `3a82f62b0d9d` | mainline | drm/amd/display: Run DC_LOG_DC after checking link->link_enc |
|  | CVE-2024-46760 | `adc539784c98` | mainline | wifi: rtw88: usb: schedule rx work after everything is set up |
|  | CVE-2024-41052 | `5a88a3f67e37` | mainline | vfio/pci: Init the count variable in collecting hot-reset devices |
|  | CVE-2024-49916 | `4b6377f0e960` | mainline | drm/amd/display: Add NULL check for clk_mgr and clk_mgr->funcs in dcn401_init_hw |
|  | CVE-2024-49893 | `58a8ee96f84d` | mainline | drm/amd/display: Check stream_status before it is used |
|  | CVE-2024-49910 | `dd340acd42c2` | mainline | drm/amd/display: Add NULL check for function pointer in dcn401_set_output_transfer_func |
|  | CVE-2024-44933 | `da03f5d1b2c3` | mainline | bnxt_en : Fix memory out-of-bounds in bnxt_fill_hw_rss_tbl() |
|  | CVE-2024-49908 | `0fe20258b498` | mainline | drm/amd/display: Add null check for 'afb' in amdgpu_dm_update_cursor (v2) |
|  | CVE-2024-50057 | `db63d9868f7f` | mainline | usb: typec: tipd: Free IRQ only if it was requested before |
|  | CVE-2024-46712 | `e9fd436bb8fb` | mainline | drm/vmwgfx: Disable coherent dumb buffers without 3d |
|  | CVE-2024-49988 | `ee426bfb9d09` | mainline | ksmbd: add refcnt to ksmbd_conn struct |
|  | CVE-2024-50097 | `6be063071a45` | mainline | net: fec: don't save PTP state if PTP is unsupported |
| does not build | CVE-2024-50217 | `aec8e6bf8391` | mainline | btrfs: fix use-after-free of block device file in __btrfs_free_extra_devids() |
|  | CVE-2024-56775 | `27227a234c14` | mainline | drm/amd/display: Fix handling of plane refcount |
|  | CVE-2024-57872 | `897df60c16d5` | mainline | scsi: ufs: pltfrm: Dellocate HBA during ufshcd_pltfrm_remove() |
|  | CVE-2024-58053 | `0e56ebde245e` | mainline | rxrpc: Fix handling of received connection abort |
|  | CVE-2024-54191 | `7a17308c1788` | mainline | Bluetooth: iso: Fix circular lock in iso_conn_big_sync |
|  | CVE-2024-57935 | `0572eccf239c` | mainline | RDMA/hns: Fix accessing invalid dip_ctx during destroying QP |
|  | CVE-2025-21634 | `3cb97a927fff` | mainline | cgroup/cpuset: remove kernfs active break |
|  | CVE-2024-57984 | `b75439c945b9` | mainline | i3c: dw: Fix use-after-free in dw_i3c_master driver due to race condition |
|  | CVE-2025-21679 | `fe4de594f7a2` | mainline | btrfs: add the missing error handling inside get_canonical_dev_path |
|  | CVE-2025-21985 | `8adbb2a98b00` | mainline | drm/amd/display: Fix out-of-bound accesses |
|  | CVE-2025-38038 | `db1cafc77aaa` | mainline | cpufreq: amd-pstate: Remove unnecessary driver_lock in set_boost |
|  | CVE-2025-21836 | `8802766324e1` | mainline | io_uring/kbuf: reallocate buf lists on upgrade |
|  | CVE-2025-38080 | `3a7810c212bc` | mainline | drm/amd/display: Increase block_sequence array size |
|  | CVE-2025-21942 | `5a4041f2c472` | mainline | btrfs: zoned: fix extent range end unlock in cow_file_range() |
|  | CVE-2025-21923 | `e53fc232a65f` | mainline | HID: hid-steam: Fix use-after-free when detaching device |
| does not build | CVE-2025-22028 | `36cef585e2a3` | mainline | media: vimc: skip .s_stream() for stopped entities |
|  | CVE-2025-22006 | `5f079290e591` | mainline | net: ethernet: ti: am65-cpsw: Fix NAPI registration sequence |
|  | CVE-2025-22043 | `542027e123fc` | mainline | ksmbd: add bounds check for durable handle context |
| does not build | CVE-2025-38099 | `14d17c78a4b1` | mainline | Bluetooth: Disable SCO support if READ_VOICE_SETTING is unsupported/broken |
|  | CVE-2025-37878 | `0ba3a4ab76fd` | mainline | perf/core: Fix WARN_ON(!ctx) in __free_event() for partial init |
|  | CVE-2025-37802 | `1df0d4c61613` | mainline | ksmbd: fix WARNING "do not call blocking ops when !TASK_RUNNING" |
|  | CVE-2025-38017 | `d9ec73301099` | mainline | fs/eventpoll: fix endless busy loop after timeout has expired |
|  | CVE-2025-38140 | `121218bef4c1` | mainline | dm: limit swapping tables for devices with zone write plugs |
|  | CVE-2025-37965 | `9984db637420` | mainline | drm/amd/display: Fix invalid context error in dml helper |
|  | CVE-2025-38014 | `a409e919ca32` | mainline | dmaengine: idxd: Refactor remove call with idxd_cleanup() helper |
|  | CVE-2025-38369 | `17502e7d7b71` | mainline | dmaengine: idxd: Check availability of workqueue allocated by idxd wq driver before using |
|  | CVE-2025-38092 | `10379171f346` | mainline | ksmbd: use list_first_entry_or_null for opinfo_get_list() |
|  | CVE-2025-38438 | `6c038b58a2dc` | mainline | ASoC: SOF: Intel: hda: Use devm_kstrdup() to avoid memleak. |
|  | CVE-2025-39762 | `158b9201c17f` | mainline | drm/amd/display: add null check |
|  | CVE-2025-38379 | `3bbe46716092` | mainline | smb: client: fix warning when reconnecting channel |
|  | CVE-2025-38411 | `9df7b5ebead6` | mainline | netfs: Fix double put of request |
| does not build | CVE-2025-38656 | `cf80c02a9fdb` | mainline | wifi: iwlwifi: Fix error code in iwl_op_mode_dvm_start() |
|  | CVE-2025-39747 | `1c8c354098ea` | mainline | drm/msm: Add error handling for krealloc in metadata setup |
|  | CVE-2025-39707 | `b4a69f7f29c8` | mainline | drm/amdgpu: check if hubbub is NULL in debugfs/amdgpu_dm_capabilities |
|  | CVE-2025-39779 | `b1511360c8ac` | mainline | btrfs: subpage: keep TOWRITE tag until folio is cleaned |
|  | CVE-2025-40339 | `859958a7faef` | mainline | drm/amdgpu: fix nullptr err of vm_handle_moved |
|  | CVE-2025-39882 | `4de37a48b6b5` | mainline | drm/mediatek: fix potential OF node use-after-free |
|  | CVE-2025-40247 | `830d68f2cb8a` | mainline | drm/msm: Fix pgtable prealloc error path |
|  | CVE-2025-40348 | `6ed8bfd24ce1` | mainline | slab: Avoid race on slab->obj_exts in alloc_slab_obj_exts |
|  | CVE-2025-40354 | `bec947cbe9a6` | mainline | drm/amd/display: increase max link count and fix link->enc NULL pointer access |
|  | CVE-2025-40266 | `103e17aac09c` | mainline | KVM: arm64: Check the untrusted offset in FF-A memory share |
|  | CVE-2025-71202 | `e37d5a2d60a3` | mainline | iommu/sva: invalidate stale IOTLB entries for kernel address space |
|  | CVE-2025-68300 | `7b6dcd9bfd86` | mainline | fs/namespace: fix reference leak in grab_requested_mnt_ns |
|  | CVE-2025-68357 | `7fd8720dff2d` | mainline | iomap: allocate s_dio_done_wq for async reads as well |
|  | CVE-2025-68299 | `d27c71257825` | mainline | afs: Fix delayed allocation of a cell's anonymous key |
|  | CVE-2026-22983 | `7d11e047eda5` | mainline | net: do not write to msg_get_inq in callee |
|  | CVE-2026-22995 | `f0d385f6689f` | mainline | ublk: fix use-after-free in ublk_partition_scan_work |
|  | CVE-2026-23117 | `42fb5f3deb58` | mainline | ice: add missing ice_deinit_hw() in devlink reinit path |
|  | CVE-2026-43161 | `42662d19839f` | mainline | iommu/vt-d: Skip dev-iotlb flush for inaccessible PCIe device without scalable mode |
|  | CVE-2026-43220 | `9e249c484128` | mainline | iommu/amd: serialize sequence allocation under concurrent TLB invalidations |
|  | CVE-2026-43137 | `16c589567a95` | mainline | ASoC: SOF: Intel: hda: Fix NULL pointer dereference |
|  | CVE-2026-23200 | `bbf4a17ad9ff` | mainline | ipv6: Fix ECMP sibling count mismatch when clearing RTF_ADDRCONF |
|  | CVE-2026-31536 | `9da82dc73cb0` | mainline | smb: server: let send_done handle a completion without IB_SEND_SIGNALED |
|  | CVE-2026-46245 | `226a40c06a18` | mainline | drm/amd/display: Fix dc_link NULL handling in HPD init |
|  | CVE-2026-43318 | `b18fc0ab8373` | mainline | drm/amdgpu: fix sync handling in amdgpu_dma_buf_move_notify |
|  | CVE-2026-23341 | `8363c0286333` | mainline | accel/amdxdna: Fix crash when destroying a suspended hardware context |
|  | CVE-2026-23288 | `1110a949675e` | mainline | accel/amdxdna: Fix out-of-bounds memset in command slot handling |
|  | CVE-2026-23348 | `96a1fd0d84b1` | mainline | cxl: Fix race of nvdimm_bus object when creating nvdimm objects |
|  | CVE-2026-43369 | `062ea905fff7` | mainline | drm/amd: Fix NULL pointer dereference in device cleanup |
|  | CVE-2026-43367 | `72ecb1dae727` | mainline | drm/amd: Fix a few more NULL pointer dereference in device cleanup |
|  | CVE-2026-31437 | `e9075e420a1e` | mainline | netfs: Fix NULL pointer dereference in netfs_unbuffered_write() on retry |
|  | CVE-2026-43070 | `a3125bc01884` | mainline | bpf: Reset register ID for BPF_END value tracking |
|  | CVE-2026-43440 | `87c2302813ab` | mainline | net/mana: Null service_wq on setup error to prevent double destroy |
|  | CVE-2026-31516 | `29fe3a61bcdc` | mainline | xfrm: prevent policy_hthresh.work from racing with netns teardown |
|  | CVE-2026-31729 | `d2d8c17ac01a` | mainline | usb: typec: ucsi: validate connector number in ucsi_notify_common() |
|  | CVE-2026-31513 | `9d87cb22195b` | mainline | Bluetooth: L2CAP: Fix stack-out-of-bounds read in l2cap_ecred_conn_req |
|  | CVE-2026-31413 | `c845894ebd6f` | mainline | bpf: Fix unsound scalar forking in maybe_fork_scalars() for BPF_OR |
|  | CVE-2026-31458 | `1bfe9fb5ed26` | mainline | mm/damon/sysfs: check contexts->nr before accessing contexts_arr[0] |
|  | CVE-2026-31742 | `40014493cece` | mainline | vt: discard stale unicode buffer on alt screen exit after resize |
|  | CVE-2026-43323 | `1319ea57529e` | mainline | sched/fair: Fix zero_vruntime tracking fix |
|  | CVE-2026-46017 | `3bac01168982` | mainline | mm: fix deferred split queue races during migration |
|  | CVE-2026-43084 | `936206e3f6ff` | mainline | netfilter: nfnetlink_queue: make hash table per queue |
|  | CVE-2026-45988 | `0422e7a4883f` | mainline | rxrpc: Fix re-decryption of RESPONSE packets |
|  | CVE-2026-46147 | `73b9c1e5da84` | mainline | KVM: arm64: Fix pin leak and publication ordering in __pkvm_init_vcpu() |
|  | CVE-2026-53285 | `183182235f6d` | mainline | drm/amd/display: Wrap DCN32 phantom-plane allocation in DC_RUN_WITH_PREEMPTION_ENABLED |
|  | CVE-2026-64060 | `5046a34f0643` | mainline | netfs: Fix leak of request in netfs_write_begin() error handling |
|  | CVE-2026-46274 | `d6a2d7b04b5a` | mainline | io-wq: check that the predecessor is hashed in io_wq_remove_pending() |
|  | CVE-2026-52966 | `dc366607c41c` | mainline | drm: Replace old pointer to new idr |
|  | CVE-2026-64212 | `d733ed481fd2` | mainline | wifi: iwlwifi: mld: don't dereference a pointer before NULL checking it |
|  | CVE-2026-98880 | `24f7d1824b75` | mainline | ntfs3: handle set_blocksize failures |
|  | CVE-2026-64016 | `3515503322f4` | mainline | ksmbd: fix durable reconnect error path file lifetime |
|  | CVE-2026-63983 | `9552b11e3eda` | mainline | net/sched: fix packet loop on netem when duplicate is on |
|  | CVE-2026-63885 | `7164d78559b0` | mainline | drm/gem: fix race between change_handle and handle_delete |
|  | CVE-2026-53243 | `6d99479799c6` | mainline | rseq: Fix using an uninitialized stack variable in rseq_exit_user_update() |
|  | CVE-2026-53143 | `352ea59028ea` | mainline | drm/amdkfd: Fix buffer overflow in SDMA queue checkpoint/restore on GFX11 |
|  | CVE-2026-53246 | `0861615c28de` | mainline | sctp: validate cached peer INIT chunk length in COOKIE_ECHO processing |
|  | CVE-2026-68205 | `06cb687a5132` | mainline | media: v4l2-fwnode: Fix subdev owner overwritten in v4l2_async_register_subdev_sensor() |
|  | CVE-2026-53156 | `5b6b6fc49189` | mainline | nvmem: core: fix use-after-free bugs in error paths |
|  | CVE-2026-53145 | `1a4f03d22fb6` | mainline | drm/gem: Try to fix change_handle ioctl, attempt 4 |
|  | CVE-2026-74342 | `6cccc49b027c` | mainline | kernfs: link kn to its parent before the LSM init hook |
|  | CVE-2026-72493 | `46762cefe7f4` | mainline | net: serialize netif_running() check in enqueue_to_backlog() |
|  | CVE-2026-63816 | `e0288584baa5` | mainline | f2fs: atomic: fix UAF issue on f2fs_inode_info.atomic_inode |
|  | CVE-2026-72376 | `c9c3b615a462` | mainline | afs: Fix misplaced inc of net->cells_outstanding |
|  | CVE-2026-72373 | `794a01110390` | mainline | afs: Fix missing NULL pointer check in afs_break_some_callbacks() |
|  | CVE-2026-68112 | `00f4050f7c36` | mainline | drm/amdgpu/gfx9.4.3: replace BUG_ON() with WARN_ON() |
|  | CVE-2026-68412 | `c6659f66d4ee` | mainline | wifi: cfg80211: Fix an error handling path in cfg80211_wext_siwscan() |
|  | CVE-2026-68337 | `3f4920d165b2` | mainline | bpf: Reject redirect helpers without a bpf_net_context |
|  | CVE-2026-74506 | `4af1ec68d54b` | mainline | afs: Fix UAF when sending a message |
|  | CVE-2026-80704 | `114b42507b6a` | mainline | drm/amd/display: use proper context for logging |
|  | CVE-2026-80820 | `527eaaefddb6` | mainline | xfs: don't livelock in scrub on a circular unlinked list |
|  | CVE-2026-74639 | `2615f0fb90df` | mainline | ALSA: us144mkii: re-anchor capture URBs on resubmission |
|  | CVE-2026-74642 | `f8a80cfb6861` | mainline | ALSA: usb: Fix UAF at delayed release of MIDI2 EPs |
|  | CVE-2026-93238 | `bf09b9d7cd78` | mainline | s390/vfio-ap: fix potential use of uninitialized apm_filtered bitmap |
|  | CVE-2026-89611 | `a83e82b0ec3a` | mainline | ntfs: validate non-resident attribute offsets |
|  | CVE-2026-89610 | `fea9e4488f38` | mainline | ntfs: verify run length exceeding volume boundary |
|  | CVE-2026-98365 | `d10e2a08799e` | mainline | RDMA/rxe: Fix integer overflow in mr_check_range() leading to OOB access |
|  | CVE-2026-97950 | `a7c1290eef60` | mainline | configfs: pin the symlink target's dirent instead of chasing ->ci_dentry |

Fix any of these with `fasttrack cve <ID>` (add `--claude` for a Claude-made backport).

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
|  | CVE-2026-52945 | `cfdb22762f90` | mainline | Revert "wireguard: device: enable threaded NAPI" — reverts a stable-only backport; mainline keeps threaded NAPI |
|  | CVE-2026-52945 | `42bc3f45425b` | mainline | Revert "wireguard: device: enable threaded NAPI" — reverts a stable-only backport; mainline keeps threaded NAPI |
|  | CVE-2026-52945 | `e94b369ff82f` | mainline | Revert "wireguard: device: enable threaded NAPI" — reverts a stable-only backport; mainline keeps threaded NAPI |
|  | CVE-2026-68086 | `2dfe9f5c91d0` | mainline | mm/khugepaged: write all dirty file folios when collapsing — 044925f9b565 removed the nr_thps code |
|  | CVE-2026-98938 | `9a7931e847f3` | mainline | rust: irq: pass RegistrationInner as cookie to request_irq — 98c63ce4d760 removed RegistrationInner |
