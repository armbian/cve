# Kernel security fast-track

**Events this run**

- added 6.18: 29 patch(es)
- added 7.3: 1 patch(es)

## 6.18 (base 6.18.59, `1253a6aa5d10`)

### Included (applies unchanged) (29)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
|  | CVE-2026-98853 | `006c8b834aed` | stable-queue | net: gso: limit recursive IP-in-IP segmentation |
|  | CVE-2026-43174 | `5d540e450895` | mainline | io_uring/zcrx: fix post open error handling |
|  | CVE-2026-53024 | `84265cbd96b9` | mainline | greybus: raw: fix use-after-free if write is called after disconnect |
|  | CVE-2026-46017 | `3bac01168982` | mainline | mm: fix deferred split queue races during migration |
|  | CVE-2026-98376 | `593980175389` | mainline | bpf: Use array_map_meta_equal for percpu array inner map replacement |
|  | CVE-2026-72397 | `828cd614e2af` | mainline | hwmon: (pmbus/core) honor vrm_version in pmbus_data2reg_vid() |
|  | CVE-2026-93044 | `34746b5a84ec` | mainline | bpf: Disallow interpreter fallback for arena-related insns |
|  | CVE-2026-100073 | `46e8e31771f4` | mainline | ext4: fix transaction overflow during writeback |
|  | CVE-2026-90256 | `2b66c83ff175` | mainline | Bluetooth: L2CAP: use proto_lock for l2cap_data to fix l2cap_disconn_ind |
|  | CVE-2026-80579 | `95e647d2a530` | mainline | fbdev: clear fb_info->mode before deleting a videomode |
|  | CVE-2026-80580 | `d15d51fb26e8` | mainline | fbdev: bound mode sysfs output to the sysfs buffer |
|  | CVE-2026-90211 | `cc3e12330599` | mainline | bpf, s390: Clear fetch destination on faulting arena atomic |
|  | CVE-2026-90098 | `b62793a7baee` | mainline | net: sparx5: fix sleep in atomic context in MAC table access |
|  | CVE-2026-99109 | `4aa2c106aef4` | mainline | smb: client: reject SetEA requests that do not fit the request buffer |
|  | CVE-2026-98364 | `9fa903b24b1f` | mainline | xfrm: hold net_device reference under RCU in bundle creation |
|  | CVE-2026-98355 | `99c24a8968eb` | mainline | RDMA/rtrs: guard against null kobj name |
|  | CVE-2026-98834 | `26300879cd8e` | mainline | mtd: core: avoid double-free of OTP NVMEM device |
|  | CVE-2026-98332 | `6f0a100df853` | mainline | wifi: mac80211: only operate on TDLS peers in the TDLS code |
|  | CVE-2026-98292 | `8879e3e0a84a` | mainline | Bluetooth: btmtksdio, btmtkuart: validate WMT event length before struct access |
|  | CVE-2026-98285 | `2842ce397dd0` | mainline | net: bridge: vlan: fix bugs caused by switchdev deletion errors |
|  | CVE-2026-98449 | `8f6f8a48399f` | mainline | smb: client: delete compound mids on send failure before unlock |
|  | CVE-2026-98824 | `6bdcdb31318c` | mainline | wifi: mac80211: validate TX status rate metadata |
|  | CVE-2026-98551 | `24b620729e53` | mainline | perf/core: Fill branch entries with a single assignment |
|  | CVE-2026-98570 | `87cd6b717e40` | mainline | net: ipv6: keep room for the mac header in dst_dev_overhead() |
|  | CVE-2026-98810 | `6f63e919fe1e` | mainline | wifi: mac80211: fix slab-out-of-bounds read in ieee80211_monitor_select_queue() |
|  | CVE-2026-98802 | `8ae3f4067ba4` | mainline | seg6: ensure packet data is writable before modifying SRH and IPv6 DA |
|  | CVE-2026-98966 | `184b5ddf82d4` | mainline | bonding: fix the program leak when XDP is replaced |
|  | CVE-2026-98954 | `44378d02c5aa` | mainline | net: always dissect GSO packets in __virtio_net_hdr_to_skb() |
|  | CVE-2026-99183 | `89c2c777df17` | mainline | accel/rocket: search every core slot when looking up a scheduler |

### Needs a manual backport (128)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
|  | CVE-2026-23377 | `e142dc4ef0f4` | stable-queue | ice: change XDP RxQ frag_size from DMA write length to xdp.frame_sz |
|  | CVE-2025-71074 | `e5bf5ee26663` | mainline | functionfs: fix the open/removal races |
|  | CVE-2025-68226 | `abd29b6e17a9` | mainline | smb: client: fix incomplete backport in cfids_invalidation_worker() |
|  | CVE-2025-71146 | `2e2a72076688` | mainline | netfilter: nf_conncount: fix leaked ct in error paths |
|  | CVE-2026-22983 | `7d11e047eda5` | mainline | net: do not write to msg_get_inq in callee |
|  | CVE-2026-23082 | `79a6d1bfe114` | mainline | can: gs_usb: gs_usb_receive_bulk_callback(): unanchor URL on usb_submit_urb() error |
|  | CVE-2026-43220 | `9e249c484128` | mainline | iommu/amd: serialize sequence allocation under concurrent TLB invalidations |
|  | CVE-2026-23200 | `bbf4a17ad9ff` | mainline | ipv6: Fix ECMP sibling count mismatch when clearing RTF_ADDRCONF |
|  | CVE-2026-52945 | `168ee1549fa2` | mainline | Revert "wireguard: device: enable threaded NAPI" |
|  | CVE-2026-52945 | `42bc3f45425b` | mainline | Revert "wireguard: device: enable threaded NAPI" |
|  | CVE-2026-52945 | `cfdb22762f90` | mainline | Revert "wireguard: device: enable threaded NAPI" |
|  | CVE-2026-52945 | `e94b369ff82f` | mainline | Revert "wireguard: device: enable threaded NAPI" |
|  | CVE-2026-23341 | `8363c0286333` | mainline | accel/amdxdna: Fix crash when destroying a suspended hardware context |
|  | CVE-2026-23288 | `1110a949675e` | mainline | accel/amdxdna: Fix out-of-bounds memset in command slot handling |
|  | CVE-2026-23355 | `aac9b27f7c1f` | mainline | ata: libata: cancel pending work after clearing deferred_qc |
|  | CVE-2026-43070 | `a3125bc01884` | mainline | bpf: Reset register ID for BPF_END value tracking |
|  | CVE-2026-53106 | `350de5b8a9be` | mainline | bpf: Do not allow deleting local storage in NMI |
|  | CVE-2026-31444 | `48623ec358c1` | mainline | ksmbd: fix use-after-free and NULL deref in smb_grant_oplock() |
|  | CVE-2026-43042 | `629ec78ef860` | mainline | mpls: add seqcount to protect the platform_label{,s} pair |
|  | CVE-2026-31742 | `40014493cece` | mainline | vt: discard stale unicode buffer on alt screen exit after resize |
|  | CVE-2026-43326 | `415cb193bb97` | mainline | sched_ext: Fix SCX_KICK_WAIT deadlock by deferring wait to balance callback |
|  | CVE-2026-74419 | `6e87001fe19f` | mainline | accel/amdxdna: Adjust size for copy_to_user() |
|  | CVE-2026-43095 | `4e53116437e9` | mainline | ASoC: SDCA: Fix errors in IRQ cleanup |
|  | CVE-2026-53091 | `7fb4c1967011` | mainline | net: pull headers in qdisc_pkt_len_segs_init() |
|  | CVE-2026-80657 | `506255d46bdb` | mainline | accel/amdxdna: Guard management mailbox channel cleanup against NULL pointer |
|  | CVE-2026-46153 | `7dddc74af369` | mainline | 8021q: delete cleared egress QoS mappings |
|  | CVE-2026-46048 | `7a5f1cd22d47` | mainline | ALSA: caiaq: fix usb_dev refcount leak on probe failure |
|  | CVE-2026-64092 | `77098e4bea37` | mainline | batman-adv: tp_meter: fix tp_vars reference leak in receiver shutdown |
|  | CVE-2026-64160 | `2c8f4742bb76` | mainline | netfs: Fix potential for tearing in ->remote_i_size and ->zero_point |
|  | CVE-2026-64139 | `af92ee994cc7` | mainline | ksmbd: fix SID memory leak in set_posix_acl_entries_dacl() on overflow |
|  | CVE-2026-52966 | `dc366607c41c` | mainline | drm: Replace old pointer to new idr |
|  | CVE-2026-64028 | `576ec047d20b` | mainline | tracing: Avoid NULL return from hist_field_name() on truncation |
|  | CVE-2026-63909 | `0e60dafe97ec` | mainline | ksmbd: OOB read regression in smb_check_perm_dacl() ACE-walk loops |
|  | CVE-2026-63977 | `d733f519f644` | mainline | dpll: zl3073x: use __dpll_device_change_ntf() and remove change_work |
|  | CVE-2026-98436 | `9480dd7ec3fc` | mainline | accel/amdxdna: Disable device buffer exporting |
|  | CVE-2026-63885 | `7164d78559b0` | mainline | drm/gem: fix race between change_handle and handle_delete |
|  | CVE-2026-53243 | `6d99479799c6` | mainline | rseq: Fix using an uninitialized stack variable in rseq_exit_user_update() |
|  | CVE-2026-74354 | `80b89d0226a0` | mainline | bpf: Take mmap_lock in zap_pages() |
|  | CVE-2026-72203 | `76bc14c7097f` | mainline | ntfs: skip extent mft records in writeback to prevent deadlock |
|  | CVE-2026-72200 | `ec4f061f2219` | mainline | ntfs: detect mapping-pairs LCN accumulator overflow |
|  | CVE-2026-74342 | `6cccc49b027c` | mainline | kernfs: link kn to its parent before the LSM init hook |
|  | CVE-2026-72198 | `097cdfd0a55d` | mainline | ntfs: reject non-resident records for resident-only attributes |
|  | CVE-2026-74314 | `a3a81d247651` | mainline | bpf: Cancel special fields on map value recycle |
|  | CVE-2026-74272 | `4dd86ca99ffc` | mainline | cxl/region: Resolve region deletion races |
|  | CVE-2026-80899 | `c37460cd9b2f` | mainline | erofs: remove fscache backend entirely |
|  | CVE-2026-93181 | `174f0582e38a` | mainline | perf/x86/intel/uncore: Fix uncore_box ref/unref ordering |
|  | CVE-2026-72377 | `81e985b4c3a6` | mainline | afs: Remove setting of AS_RELEASE_ALWAYS for symlinks and mountpoints |
|  | CVE-2026-68447 | `426ffae6ecc7` | mainline | drm/amdkfd: clamp v9 CRIU control stack checkpoint copy to BO size |
|  | CVE-2026-68103 | `a609b6278bf3` | mainline | drm/amdgpu: reject mapping a reserved doorbell to a new queue |
|  | CVE-2026-93135 | `f1c27922576e` | mainline | bpf: Reject programs with inlined helpers if JIT is not available |
|  | CVE-2026-98926 | `8fa813b7fd1e` | mainline | drm/amd/display: Remove sink usage from DPMS |
|  | CVE-2026-98815 | `9952f3882ecb` | mainline | nvme: fix cdev lifetime |
|  | CVE-2026-93047 | `fa98563ab00d` | mainline | drm/v3d: Associate BOs with every job that accesses them |
|  | CVE-2026-93270 | `7a0855e73757` | mainline | bpf: Disallow interpreter fallback for BPF_ADDR_PERCPU insn |
|  | CVE-2026-74533 | `af24e338bf5d` | mainline | Bluetooth: ISO: fix race of kfree vs kref_get_unless_zero |
|  | CVE-2026-93216 | `90f095b816e2` | mainline | mm/page_owner: use memcg_data snapshot to avoid TOCTOU in print_page_owner_memcg() |
|  | CVE-2026-80889 | `050f010f920d` | mainline | can: isotp: fix timer drain order, wakeup handling and tx_gen ordering |
|  | CVE-2026-89584 | `14b007e17881` | mainline | block: validate user space vectors during extraction |
|  | CVE-2026-90321 | `8914a3330b72` | mainline | ocfs2: validate inline xattrs during inode block validation |
|  | CVE-2026-90320 | `2cf82b46d5e4` | mainline | ocfs2: validate external xattr entries when reading metadata |
|  | CVE-2026-80728 | `b96c529cd255` | mainline | Revert "drm/amdgpu: fix aperture mapping leak" |
|  | CVE-2026-89772 | `5376c9db4536` | mainline | btrfs: write-protect folios during data writeback |
|  | CVE-2026-74752 | `3dbb44d88b1e` | mainline | sctp: validate cookie AUTH state before use |
|  | CVE-2026-80785 | `061db6b7a910` | mainline | fbdev: serialize mode sysfs access with lock_fb_info() |
|  | CVE-2026-98869 | `7ce090afbf72` | mainline | bpf: Infer zext_dst based on static register liveness analysis |
|  | CVE-2026-90237 | `3679da4ad8be` | mainline | netfilter: nft_ct: move custom expectation support to helper |
|  | CVE-2026-100072 | `a9ba4dd2f18b` | mainline | ACPI: platform: Use acpi_bus_get_primary_device() |
|  | CVE-2026-98439 | `4fd5bad647bf` | mainline | smb/server: cancel async requests when closing connection |
|  | CVE-2026-99101 | `0ab6dc1ac460` | mainline | ntfs: move attribute payload before shrinking its record |
|  | CVE-2026-89611 | `a83e82b0ec3a` | mainline | ntfs: validate non-resident attribute offsets |
|  | CVE-2026-89610 | `fea9e4488f38` | mainline | ntfs: verify run length exceeding volume boundary |
|  | CVE-2026-98153 | `56e1c6bbe4bb` | mainline | nvme: fix racy access to FDP placement id array |
|  | CVE-2026-89632 | `05f78e6cf34e` | mainline | smb: client: fix use-before-check of ReparseDataLength in reparse_buf_ptr() |
|  | CVE-2026-89755 | `34a00895d032` | mainline | mm/migrate_device: clear stale mapping after freeing swapcache |
|  | CVE-2026-98125 | `01261a6fa48b` | mainline | smb/client: fix stale page cache in insert/collapse range |
|  | CVE-2026-98124 | `448ba0ae65ca` | mainline | smb/client: invalidate fscache for fallocate range operations |
|  | CVE-2026-98118 | `fed0b33e6c58` | mainline | netfs: Fix readahead synchronisation issues by loading all folios upfront |
|  | CVE-2026-98115 | `d12168084c8c` | mainline | ksmbd: safely drain sessions during logoff |
|  | CVE-2026-99125 | `f3110e969ad2` | mainline | s390/pai: Handle multiple PMU stop callback invocations |
|  | CVE-2026-98106 | `c4126f1db36e` | mainline | drm/pagemap: Prevent double migration of device pages |
|  | CVE-2026-99076 | `ac76cab50e89` | mainline | ipv6: udp: Create exceptions before socket matching |
|  | CVE-2026-98692 | `12f5d8b85a66` | mainline | thunderbolt: Make the DP tunnel activation callback mandatory |
|  | CVE-2026-98652 | `f3a557067d57` | mainline | KVM: s390: Add missing srcu in kvm_s390_set_irq_state() |
|  | CVE-2026-98431 | `a44a3f175eae` | mainline | RDMA/uverbs: Fix mmap_lock/disassociation_lock circular dependency |
|  | CVE-2026-89788 | `b5ec6c462aab` | mainline | ksmbd: fix tree connection use-after-free in smb2_tree_connect() |
|  | CVE-2026-89805 | `df72e55e754c` | mainline | drm/pagemap: Fix folio allocation fallback and use-after-put |
|  | CVE-2026-97563 | `5be5bdda5863` | mainline | smb: client: reject out-of-bounds DataOffset in CIFSSMBRead() |
|  | CVE-2026-97526 | `9ecc4d033879` | mainline | s390/pai: Support CPU hotplug for PMU PAI |
|  | CVE-2026-98228 | `bbc448c541ed` | mainline | mips: select CONFIG_WEAK_REORDERING_BEYOND_LLSC from CONFIG_EYEQ |
|  | CVE-2026-98338 | `708f9d43d6a2` | mainline | wifi: cfg80211: ibss: ref BSS entry for joined event |
|  | CVE-2026-98333 | `78183e833195` | mainline | wifi: mac80211: reset the LED state when ifup fails |
|  | CVE-2026-97538 | `8042312e73c5` | mainline | hwmon: (asus_rog_ryujin) Validate HID report lengths |
|  | CVE-2026-98318 | `23c240d9509e` | mainline | smb: client: validate absolute native symlink targets before NT fixups |
|  | CVE-2026-98420 | `d7fd1f98607f` | mainline | ksmbd: follow SMB2 session expiration semantics |
|  | CVE-2026-98288 | `15989abd74f1` | mainline | net: stmmac: fix TSO header length truncation |
|  | CVE-2026-98284 | `ceac0de741bf` | mainline | netlink: do not free nlk->groups while lockless readers can use it |
|  | CVE-2026-98427 | `7f4a5ec6258f` | mainline | net/sched: codel: bound the dropping loop per dequeue call |
|  | CVE-2026-98444 | `ffb48dccce19` | mainline | xfs: drop dquot flush lock when we can't find a buffer to flush |
|  | CVE-2026-98176 | `c883d0a132d4` | mainline | drm/amdkfd: Avoid integer underflow with ffs in EOP ring size calc |
|  | CVE-2026-98177 | `8ee521b8b189` | mainline | drm/amdkfd: Avoid integer underflow in EOP ring size calculation. |
|  | CVE-2026-98628 | `261b61d3735b` | mainline | bpf: Make post-verification instruction rewrites killable |
|  | CVE-2026-98617 | `b5d9e9d4d0c1` | mainline | eth: fbnic: use the Rx queue napi pointer to find the napi vector |
|  | CVE-2026-98599 | `79a9172f3ab4` | mainline | bpf: Reject non-negative offsets in stack_slot_obj_get_spi() |
|  | CVE-2026-98589 | `a6c1edfbe240` | mainline | bpf: Reject pkt arguments in mutating subprogs |
|  | CVE-2026-98747 | `499485a67fba` | mainline | serial: core: fix NULL pointer dereference in serial_core_unregister_port() |
|  | CVE-2026-98818 | `af2fb3ee6679` | mainline | mm/slab: do not wake up kswapd in __kfree_rcu_sheaf() |
|  | CVE-2026-98562 | `3173cba11701` | mainline | net: libwx: fix races in Tx timestamp handling |
|  | CVE-2026-98558 | `06e3f54e8b22` | mainline | net: flush skb_defer_nodes in dev_cpu_dead() |
|  | CVE-2026-98816 | `ad139384ecdd` | mainline | bpf: Fix overflow of jump offset in constant blinding |
|  | CVE-2026-98814 | `72ece656abd4` | mainline | nvme: fix command effects log lifetime for multipath heads |
|  | CVE-2026-98715 | `60d93c27859f` | mainline | KVM: SVM: Preserve TLB control (i.e. pending TLB flush) on failed VMRUN |
|  | CVE-2026-98714 | `e27fc915c8f5` | mainline | KVM: SVM: Update control fields on #VMEXIT if and only if VMRUN succeeded |
|  | CVE-2026-98806 | `056994563935` | mainline | octeontx2-pf: Fix aura BPID assignment when CONFIG_DCB is enabled |
|  | CVE-2026-98800 | `0fb5751a6e41` | mainline | bpf: Wait for an RCU tasks grace period before freeing trampoline progs |
|  | CVE-2026-98799 | `17637e1a581a` | mainline | bpf: Skip detached progs in trampoline images that are still in use |
|  | CVE-2026-99009 | `ac022970e9fb` | mainline | Bluetooth: RFCOMM: connect the session socket without rfcomm_mutex |
|  | CVE-2026-98685 | `4721587f96cb` | mainline | smb: client: discard post-EOF pagecache when extending a file via clone range |
|  | CVE-2026-98682 | `c9b1194e8ec9` | mainline | smb: client: drain and invalidate before server-side copy/clone |
|  | CVE-2026-98972 | `e06b678e3b4e` | mainline | cgroup/cpuset: Don't access cpuset_cgrp_subsys.root in is_in_v2_mode() |
|  | CVE-2026-98789 | `fbd97dd1d3ce` | mainline | bpf: Fix objects stuck in free_by_rcu_ttrace |
|  | CVE-2026-98786 | `217f64f348c9` | mainline | drm/amd/display: guard dc_sink dereferences in MST mode validation |
|  | CVE-2026-98788 | `f35e3b578422` | mainline | futex: Fix private hash use-after-free on resize |
|  | CVE-2026-98960 | `51562a8cb116` | mainline | btrfs: don't stash io_uring encoded data across -EAGAIN |
|  | CVE-2026-98938 | `9a7931e847f3` | mainline | rust: irq: pass RegistrationInner as cookie to request_irq |
|  | CVE-2026-98951 | `59052a88ba5f` | mainline | riscv: ptrace: Zero-initialize regset buffers before copyin |
|  | CVE-2026-98946 | `6abc8e4dcfbc` | mainline | drm/vc4: Disable the V3D interrupt across runtime suspend |
|  | CVE-2026-99172 | `f0e48172a59e` | mainline | ipc: drop the mqueue mount with kern_unmount() on setup failure |
|  | CVE-2026-99151 | `55a67aa89342` | mainline | drm/amd/display: Fix NULL sink dereference in USB4 bandwidth functions |

### Already in tree (126)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
|  | CVE-2026-72198, CVE-2026-72200, CVE-2026-72203 | `7ffa8f3d3023` | mainline | ntfs: reject non-resident records for resident-only attributes |
|  | CVE-2024-26626 | `e622502c310f` | mainline | ipmr: fix kernel panic when forwarding mcast packets |
|  | CVE-2024-27023 | `855678ed8534` | mainline | md: Fix missing release of 'active_io' for flush |
|  | CVE-2024-26780 | `25236c91b5ab` | mainline | af_unix: Fix task hung while purging oob_skb in GC. |
|  | CVE-2024-26710 | `f1acb109505d` | mainline | powerpc/kasan: Limit KASAN thread size increase to 32KB |
|  | CVE-2024-26750 | `aa82ac51d633` | mainline | af_unix: Drop oob_skb ref before purging queue in GC. |
|  | CVE-2024-26781 | `d6a9608af9a7` | mainline | mptcp: fix possible deadlock in subflow diag |
|  | CVE-2024-26800 | `13114dc55430` | mainline | tls: fix use-after-free on failed backlog decryption |
|  | CVE-2024-26792 | `e2b54eaf28df` | mainline | btrfs: fix double free of anonymous device after snapshot creation failure |
|  | CVE-2024-27411 | `f6ecfdad359a` | mainline | drm/nouveau: keep DMA buffers required for suspend/resume |
|  | CVE-2024-35824 | `ac3e0384073b` | mainline | misc: lis3lv02d_i2c: Fix regulators getting en-/dis-abled twice on suspend/resume |
|  | CVE-2024-35815 | `961ebd120565` | mainline | fs/aio: Check IOCB_AIO_RW before the struct aio_kiocb conversion |
|  | CVE-2024-26997 | `eed04fa96c48` | mainline | usb: dwc2: host: Fix dereference issue in DDMA completion flow. |
|  | CVE-2024-35962 | `65acf6e0501a` | mainline | netfilter: complete validation of user input |
|  | CVE-2024-35957 | `89436f4f5412` | mainline | iommu/vt-d: Fix WARN_ON in iommu probe path |
|  | CVE-2024-35996 | `fe42754b94a4` | mainline | cpu: Re-enable CPU mitigations by default for !X86 architectures |
|  | CVE-2024-36002 | `38d7b94e81d0` | mainline | dpll: fix dpll_pin_on_pin_register() for multiple parent pins |
|  | CVE-2024-35983 | `5af385f5f4cd` | mainline | bounds: Use the right number of bits for power-of-two CONFIG_NR_CPUS |
|  | CVE-2024-36887 | `387f295cb215` | mainline | e1000e: change usleep_range to udelay in PHY mdic access |
|  | CVE-2024-36962 | `e0863634bf9f` | mainline | net: ks8851: Queue RX packets in IRQ handler instead of disabling BHs |
|  | CVE-2024-36944 | `3628e0383dd3` | mainline | Reapply "drm/qxl: simplify qxl_fence_wait" |
|  | CVE-2024-36288 | `4a77c3dead97` | mainline | SUNRPC: Fix loop termination condition in gss_free_in_token_pages() |
|  | CVE-2024-40921 | `36c92936e868` | mainline | net: bridge: mst: pass vlan group directly to br_mst_vlan_set_state |
|  | CVE-2024-40920 | `546ceb1dfdac` | mainline | net: bridge: mst: fix suspicious rcu usage in br_mst_set_state |
|  | CVE-2024-40993 | `8ecd06277a76` | mainline | netfilter: ipset: Fix suspicious rcu_dereference_protected() |
|  | CVE-2024-42103 | `48f091fd50b2` | mainline | btrfs: fix adding block group to a reclaim list and the unused list during reclaim |
|  | CVE-2024-41052 | `5a88a3f67e37` | mainline | vfio/pci: Init the count variable in collecting hot-reset devices |
|  | CVE-2024-43897 | `89add40066f9` | mainline | net: drop bad gso csum_start and offset in virtio_net_hdr |
|  | CVE-2024-44968 | `6881e75237a8` | mainline | tick/broadcast: Move per CPU pointer access into the atomic section |
|  | CVE-2024-44933 | `da03f5d1b2c3` | mainline | bnxt_en : Fix memory out-of-bounds in bnxt_fill_hw_rss_tbl() |
|  | CVE-2024-46712 | `e9fd436bb8fb` | mainline | drm/vmwgfx: Disable coherent dumb buffers without 3d |
|  | CVE-2024-46734 | `cd9253c23aed` | mainline | btrfs: fix race between direct IO write and fsync when using same fd |
|  | CVE-2024-46865 | `4c8002277167` | mainline | fou: fix initialization of grc |
|  | CVE-2024-49854 | `1ba0403ac644` | mainline | block, bfq: fix uaf for accessing waker_bfqq after splitting |
|  | CVE-2024-50097 | `6be063071a45` | mainline | net: fec: don't save PTP state if PTP is unsupported |
|  | CVE-2024-50210 | `6e62807c7fbb` | mainline | posix-clock: posix-clock: Fix unbalanced locking in pc_clock_settime() |
|  | CVE-2024-53097 | `704573851b51` | mainline | mm: krealloc: Fix MTE false alarm in __do_krealloc |
|  | CVE-2024-50249 | `1c10941e34c5` | mainline | ACPI: CPPC: Make rmw_lock a raw_spin_lock |
|  | CVE-2024-50241 | `63fab04cbd0f` | mainline | NFSD: Initialize struct nfsd4_copy earlier |
|  | CVE-2024-53073 | `8286f8b62299` | mainline | NFSD: Never decrement pending_async_copies on error |
|  | CVE-2024-53060 | `a6dd15981c03` | mainline | drm/amdgpu: prevent NULL pointer dereference if ATIF is not supported |
|  | CVE-2024-53070 | `9cfb31e4c89d` | mainline | usb: dwc3: fix fault at system suspend if device was already runtime suspended |
|  | CVE-2024-53136 | `d1aa0c04294e` | mainline | mm: revert "mm: shmem: fix data-race in shmem_getattr()" |
|  | CVE-2024-56766 | `d8e4771f99c0` | mainline | mtd: rawnand: fix double free in atmel_pmecc_create_user() |
|  | CVE-2024-56661 | `b04d86fff66b` | mainline | tipc: fix NULL deref in cleanup_bearer() |
|  | CVE-2024-54191 | `7a17308c1788` | mainline | Bluetooth: iso: Fix circular lock in iso_conn_big_sync |
|  | CVE-2024-41149 | `85672ca9ceea` | mainline | block: avoid to reuse `hctx` not removed from cpuhp callback list |
|  | CVE-2024-46896 | `a93b1020eb93` | mainline | drm/amdgpu: don't access invalid sched |
|  | CVE-2024-57935 | `0572eccf239c` | mainline | RDMA/hns: Fix accessing invalid dip_ctx during destroying QP |
|  | CVE-2024-54031 | `542ed8145e6f` | mainline | netfilter: nft_set_hash: unaligned atomic read on struct nft_set_ext |
|  | CVE-2024-57930 | `afc6717628f9` | mainline | tracing: Have process_string() also allow arrays |
|  | CVE-2025-21671 | `212fe1c0df4a` | mainline | zram: fix potential UAF of zram table |
|  | CVE-2025-21817 | `7c0be4ead1f8` | mainline | block: mark GFP_NOIO around sysfs ->store() |
|  | CVE-2025-21679 | `fe4de594f7a2` | mainline | btrfs: add the missing error handling inside get_canonical_dev_path |
|  | CVE-2025-21794 | `0b43d98ff29b` | mainline | HID: hid-thrustmaster: fix stack-out-of-bounds read in usb_check_int_endpoints() |
|  | CVE-2025-21886 | `3d8c6f26893d` | mainline | RDMA/mlx5: Fix implicit ODP hang on parent deregistration |
|  | CVE-2025-21942 | `5a4041f2c472` | mainline | btrfs: zoned: fix extent range end unlock in cow_file_range() |
|  | CVE-2025-21923 | `e53fc232a65f` | mainline | HID: hid-steam: Fix use-after-free when detaching device |
|  | CVE-2025-22006 | `5f079290e591` | mainline | net: ethernet: ti: am65-cpsw: Fix NAPI registration sequence |
|  | CVE-2025-38099 | `14d17c78a4b1` | mainline | Bluetooth: Disable SCO support if READ_VOICE_SETTING is unsupported/broken |
|  | CVE-2025-37878 | `0ba3a4ab76fd` | mainline | perf/core: Fix WARN_ON(!ctx) in __free_event() for partial init |
|  | CVE-2025-37871 | `a1d14d931bf7` | mainline | nfsd: decrease sc_count directly if fail to queue dl_recall |
|  | CVE-2025-37929 | `fee4d171451c` | mainline | arm64: errata: Add missing sentinels to Spectre-BHB MIDR arrays |
|  | CVE-2025-37962 | `eb4447bcce91` | mainline | ksmbd: fix memory leak in parse_lease_state() |
|  | CVE-2025-38017 | `d9ec73301099` | mainline | fs/eventpoll: fix endless busy loop after timeout has expired |
|  | CVE-2025-37953 | `376947861013` | mainline | sch_htb: make htb_deactivate() idempotent |
|  | CVE-2025-37965 | `9984db637420` | mainline | drm/amd/display: Fix invalid context error in dml helper |
|  | CVE-2025-38092 | `10379171f346` | mainline | ksmbd: use list_first_entry_or_null for opinfo_get_list() |
|  | CVE-2025-38404 | `099cf1fbb8af` | mainline | usb: typec: displayport: Fix potential deadlock |
|  | CVE-2025-38379 | `3bbe46716092` | mainline | smb: client: fix warning when reconnecting channel |
|  | CVE-2025-38411 | `9df7b5ebead6` | mainline | netfs: Fix double put of request |
|  | CVE-2025-38656 | `cf80c02a9fdb` | mainline | wifi: iwlwifi: Fix error code in iwl_op_mode_dvm_start() |
|  | CVE-2025-38736 | `24ef2f53c07f` | mainline | net: usb: asix_devices: Fix PHY address mask in MDIO bus initialization |
|  | CVE-2025-39965 | `cd8ae32e4e46` | mainline | xfrm: xfrm_alloc_spi shouldn't use 0 as SPI |
|  | CVE-2025-39882 | `4de37a48b6b5` | mainline | drm/mediatek: fix potential OF node use-after-free |
|  | CVE-2025-40022 | `d0ca0df179c4` | mainline | crypto: af_alg - Fix incorrect boolean values in af_alg_ctx |
|  | CVE-2025-40090 | `88f170814fea` | mainline | ksmbd: fix recursive locking in RPC handle list access |
|  | CVE-2025-40348 | `6ed8bfd24ce1` | mainline | slab: Avoid race on slab->obj_exts in alloc_slab_obj_exts |
|  | CVE-2025-68252 | `fff111bf45cb` | mainline | misc: fastrpc: Fix dma_buf object leak in fastrpc_map_lookup |
|  | CVE-2025-68300 | `7b6dcd9bfd86` | mainline | fs/namespace: fix reference leak in grab_requested_mnt_ns |
|  | CVE-2025-68357 | `7fd8720dff2d` | mainline | iomap: allocate s_dio_done_wq for async reads as well |
|  | CVE-2025-68291 | `f07f4ea53e22` | mainline | mptcp: Initialise rcv_mss before calling tcp_send_active_reset() in mptcp_do_fastclose(). |
|  | CVE-2025-68299 | `d27c71257825` | mainline | afs: Fix delayed allocation of a cell's anonymous key |
|  | CVE-2025-71145 | `b4b64fda4d30` | mainline | usb: phy: isp1301: fix non-OF device reference imbalance |
|  | CVE-2026-22988 | `c92510f5e3f8` | mainline | arp: do not assume dev_hard_header() does not change skb->head |
|  | CVE-2026-22995 | `f0d385f6689f` | mainline | ublk: fix use-after-free in ublk_partition_scan_work |
|  | CVE-2026-45892 | `6d882ea3b093` | mainline | ext4: drop extent cache after doing PARTIAL_VALID1 zeroout |
|  | CVE-2026-23117 | `42fb5f3deb58` | mainline | ice: add missing ice_deinit_hw() in devlink reinit path |
|  | CVE-2026-23155 | `494fc029f662` | mainline | can: gs_usb: gs_usb_receive_bulk_callback(): fix error message |
|  | CVE-2026-23202 | `bf4528ab28e2` | mainline | spi: tegra210-quad: Protect curr_xfer in tegra_qspi_combined_seq_xfer |
|  | CVE-2026-23207 | `edf9088b6e1d` | mainline | spi: tegra210-quad: Protect curr_xfer check in IRQ handler |
|  | CVE-2026-23309 | `457965c13f08` | mainline | tracing: Add NULL pointer check to trigger_data_free() |
|  | CVE-2026-43369 | `062ea905fff7` | mainline | drm/amd: Fix NULL pointer dereference in device cleanup |
|  | CVE-2026-43367 | `72ecb1dae727` | mainline | drm/amd: Fix a few more NULL pointer dereference in device cleanup |
|  | CVE-2026-31437 | `e9075e420a1e` | mainline | netfs: Fix NULL pointer dereference in netfs_unbuffered_write() on retry |
|  | CVE-2026-43371 | `881a0263d502` | mainline | net: macb: Shuffle the tx ring before enabling tx |
|  | CVE-2026-43440 | `87c2302813ab` | mainline | net/mana: Null service_wq on setup error to prevent double destroy |
|  | CVE-2026-23451 | `b7405dcf7385` | mainline | bonding: prevent potential infinite loop in bond_header_parse() |
|  | CVE-2026-23443 | `bf504b229cb8` | mainline | ACPI: processor: Fix previous acpi_processor_errata_piix4() fix |
|  | CVE-2026-31573 | `e8d97c270cb4` | mainline | media: verisilicon: Fix kernel panic due to __initconst misuse |
|  | CVE-2026-31727 | `e002e92e88e1` | mainline | usb: gadget: u_ether: Fix NULL pointer deref in eth_get_drvinfo |
|  | CVE-2026-31513 | `9d87cb22195b` | mainline | Bluetooth: L2CAP: Fix stack-out-of-bounds read in l2cap_ecred_conn_req |
|  | CVE-2026-31413 | `c845894ebd6f` | mainline | bpf: Fix unsound scalar forking in maybe_fork_scalars() for BPF_OR |
|  | CVE-2026-43067 | `bb81702370fa` | mainline | ext4: handle wraparound when searching for blocks for indirect mapped blocks |
|  | CVE-2026-43323 | `1319ea57529e` | mainline | sched/fair: Fix zero_vruntime tracking fix |
|  | CVE-2026-43084 | `936206e3f6ff` | mainline | netfilter: nfnetlink_queue: make hash table per queue |
|  | CVE-2026-64016 | `3515503322f4` | mainline | ksmbd: fix durable reconnect error path file lifetime |
|  | CVE-2026-64240 | `171022c7d594` | mainline | media: rc: igorplugusb: fix control request setup packet |
|  | CVE-2026-53265 | `d3f0a606b9f2` | mainline | dm cache policy smq: check allocation under invalidate lock |
|  | CVE-2026-53163 | `40a25d59e85b` | mainline | locking/rtmutex: Skip remove_waiter() when waiter is not enqueued |
|  | CVE-2026-53145 | `1a4f03d22fb6` | mainline | drm/gem: Try to fix change_handle ioctl, attempt 4 |
|  | CVE-2026-68086 | `2dfe9f5c91d0` | mainline | mm/khugepaged: write all dirty file folios when collapsing |
|  | CVE-2026-64257 | `8986c932905e` | mainline | smb: client: reject overlapping data areas in SMB2 responses |
|  | CVE-2026-98870 | `b10665730fbf` | mainline | ksmbd: remove stale channels from all sessions on teardown |
|  | CVE-2026-68427 | `266cddf7bd0f` | mainline | gpu: host1x: Fix use-after-free in host1x_bo_clear_cached_mappings |
|  | CVE-2026-68344 | `71132cedd1ec` | mainline | usb: atm: ueagle-atm: reject descriptors that confuse probe and disconnect |
|  | CVE-2026-68434 | `7fb13fd7e9a5` | mainline | serial: 8250_mid: Fix NULL function pointer dereference on DNV/ICX-D/SNR platforms |
|  | CVE-2026-74639 | `2615f0fb90df` | mainline | ALSA: us144mkii: re-anchor capture URBs on resubmission |
|  | CVE-2026-74753 | `fa091f46c383` | mainline | perf: Reject exited events as group leaders |
|  | CVE-2026-74642 | `f8a80cfb6861` | mainline | ALSA: usb: Fix UAF at delayed release of MIDI2 EPs |
|  | CVE-2026-98353 | `00baeade709f` | mainline | RDMA/erdma: Use IRQ-safe XArray helpers for QP and CQ tables |
|  | CVE-2026-98316 | `221253723dc5` | mainline | ALSA: bcd2000: Fix race between rawmidi and disconnect |
|  | CVE-2026-98939 | `e3ee38c1bc0b` | mainline | x86/mm: Drop unnecessary PMD page copy when freeing |
|  | CVE-2026-98719 | `8abbc76120a7` | mainline | KVM: SEV: Nullify "have run CPUs" mask pointer when freeing it |
|  | CVE-2026-98718 | `973ea70393e8` | mainline | KVM: SEV: Do cache maintenance on the source VM *before* clearing SEV state |
|  | CVE-2026-99093 | `2fb552b0bee7` | mainline | mm: don't schedule deferred kernel page table freeing while booting |

Fix any of these with `fasttrack cve <ID>` (add `--claude` for a Claude-made backport).

## 7.3 (base 7.3.0, `c03c1a14507d`)

### Included (applies unchanged) (1)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
|  | CVE-2026-98941 | `40554d1221e3` | mainline | ext4: don't enable large folios on encrypted inodes |

### Needs a manual backport (7)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
|  | CVE-2025-68226 | `abd29b6e17a9` | mainline | smb: client: fix incomplete backport in cfids_invalidation_worker() |
|  | CVE-2026-52945 | `168ee1549fa2` | mainline | Revert "wireguard: device: enable threaded NAPI" |
|  | CVE-2026-52945 | `42bc3f45425b` | mainline | Revert "wireguard: device: enable threaded NAPI" |
|  | CVE-2026-52945 | `cfdb22762f90` | mainline | Revert "wireguard: device: enable threaded NAPI" |
|  | CVE-2026-52945 | `e94b369ff82f` | mainline | Revert "wireguard: device: enable threaded NAPI" |
|  | CVE-2026-68086 | `2dfe9f5c91d0` | mainline | mm/khugepaged: write all dirty file folios when collapsing |
|  | CVE-2026-98938 | `9a7931e847f3` | mainline | rust: irq: pass RegistrationInner as cookie to request_irq |

### Already in tree (147)

| | CVE | Upstream | Source | Subject |
|---|---|---|---|---|
|  | CVE-2024-26626 | `e622502c310f` | mainline | ipmr: fix kernel panic when forwarding mcast packets |
|  | CVE-2024-27023 | `855678ed8534` | mainline | md: Fix missing release of 'active_io' for flush |
|  | CVE-2024-26780 | `25236c91b5ab` | mainline | af_unix: Fix task hung while purging oob_skb in GC. |
|  | CVE-2024-26710 | `f1acb109505d` | mainline | powerpc/kasan: Limit KASAN thread size increase to 32KB |
|  | CVE-2024-26750 | `aa82ac51d633` | mainline | af_unix: Drop oob_skb ref before purging queue in GC. |
|  | CVE-2024-26781 | `d6a9608af9a7` | mainline | mptcp: fix possible deadlock in subflow diag |
|  | CVE-2024-26800 | `13114dc55430` | mainline | tls: fix use-after-free on failed backlog decryption |
|  | CVE-2024-26792 | `e2b54eaf28df` | mainline | btrfs: fix double free of anonymous device after snapshot creation failure |
|  | CVE-2024-27411 | `f6ecfdad359a` | mainline | drm/nouveau: keep DMA buffers required for suspend/resume |
|  | CVE-2024-35824 | `ac3e0384073b` | mainline | misc: lis3lv02d_i2c: Fix regulators getting en-/dis-abled twice on suspend/resume |
|  | CVE-2024-35815 | `961ebd120565` | mainline | fs/aio: Check IOCB_AIO_RW before the struct aio_kiocb conversion |
|  | CVE-2024-26997 | `eed04fa96c48` | mainline | usb: dwc2: host: Fix dereference issue in DDMA completion flow. |
|  | CVE-2024-35962 | `65acf6e0501a` | mainline | netfilter: complete validation of user input |
|  | CVE-2024-35957 | `89436f4f5412` | mainline | iommu/vt-d: Fix WARN_ON in iommu probe path |
|  | CVE-2024-35996 | `fe42754b94a4` | mainline | cpu: Re-enable CPU mitigations by default for !X86 architectures |
|  | CVE-2024-36002 | `38d7b94e81d0` | mainline | dpll: fix dpll_pin_on_pin_register() for multiple parent pins |
|  | CVE-2024-35983 | `5af385f5f4cd` | mainline | bounds: Use the right number of bits for power-of-two CONFIG_NR_CPUS |
|  | CVE-2024-36887 | `387f295cb215` | mainline | e1000e: change usleep_range to udelay in PHY mdic access |
|  | CVE-2024-36962 | `e0863634bf9f` | mainline | net: ks8851: Queue RX packets in IRQ handler instead of disabling BHs |
|  | CVE-2024-36944 | `3628e0383dd3` | mainline | Reapply "drm/qxl: simplify qxl_fence_wait" |
|  | CVE-2024-36288 | `4a77c3dead97` | mainline | SUNRPC: Fix loop termination condition in gss_free_in_token_pages() |
|  | CVE-2024-40921 | `36c92936e868` | mainline | net: bridge: mst: pass vlan group directly to br_mst_vlan_set_state |
|  | CVE-2024-40920 | `546ceb1dfdac` | mainline | net: bridge: mst: fix suspicious rcu usage in br_mst_set_state |
|  | CVE-2024-40993 | `8ecd06277a76` | mainline | netfilter: ipset: Fix suspicious rcu_dereference_protected() |
|  | CVE-2024-42103 | `48f091fd50b2` | mainline | btrfs: fix adding block group to a reclaim list and the unused list during reclaim |
|  | CVE-2024-41052 | `5a88a3f67e37` | mainline | vfio/pci: Init the count variable in collecting hot-reset devices |
|  | CVE-2024-43897 | `89add40066f9` | mainline | net: drop bad gso csum_start and offset in virtio_net_hdr |
|  | CVE-2024-44968 | `6881e75237a8` | mainline | tick/broadcast: Move per CPU pointer access into the atomic section |
|  | CVE-2024-44933 | `da03f5d1b2c3` | mainline | bnxt_en : Fix memory out-of-bounds in bnxt_fill_hw_rss_tbl() |
|  | CVE-2024-46712 | `e9fd436bb8fb` | mainline | drm/vmwgfx: Disable coherent dumb buffers without 3d |
|  | CVE-2024-46734 | `cd9253c23aed` | mainline | btrfs: fix race between direct IO write and fsync when using same fd |
|  | CVE-2024-46865 | `4c8002277167` | mainline | fou: fix initialization of grc |
|  | CVE-2024-49854 | `1ba0403ac644` | mainline | block, bfq: fix uaf for accessing waker_bfqq after splitting |
|  | CVE-2024-50097 | `6be063071a45` | mainline | net: fec: don't save PTP state if PTP is unsupported |
|  | CVE-2024-50210 | `6e62807c7fbb` | mainline | posix-clock: posix-clock: Fix unbalanced locking in pc_clock_settime() |
|  | CVE-2024-53097 | `704573851b51` | mainline | mm: krealloc: Fix MTE false alarm in __do_krealloc |
|  | CVE-2024-50249 | `1c10941e34c5` | mainline | ACPI: CPPC: Make rmw_lock a raw_spin_lock |
|  | CVE-2024-50241 | `63fab04cbd0f` | mainline | NFSD: Initialize struct nfsd4_copy earlier |
|  | CVE-2024-53073 | `8286f8b62299` | mainline | NFSD: Never decrement pending_async_copies on error |
|  | CVE-2024-53060 | `a6dd15981c03` | mainline | drm/amdgpu: prevent NULL pointer dereference if ATIF is not supported |
|  | CVE-2024-53070 | `9cfb31e4c89d` | mainline | usb: dwc3: fix fault at system suspend if device was already runtime suspended |
|  | CVE-2024-53136 | `d1aa0c04294e` | mainline | mm: revert "mm: shmem: fix data-race in shmem_getattr()" |
|  | CVE-2024-56766 | `d8e4771f99c0` | mainline | mtd: rawnand: fix double free in atmel_pmecc_create_user() |
|  | CVE-2024-56661 | `b04d86fff66b` | mainline | tipc: fix NULL deref in cleanup_bearer() |
|  | CVE-2024-54191 | `7a17308c1788` | mainline | Bluetooth: iso: Fix circular lock in iso_conn_big_sync |
|  | CVE-2024-41149 | `85672ca9ceea` | mainline | block: avoid to reuse `hctx` not removed from cpuhp callback list |
|  | CVE-2024-46896 | `a93b1020eb93` | mainline | drm/amdgpu: don't access invalid sched |
|  | CVE-2024-57935 | `0572eccf239c` | mainline | RDMA/hns: Fix accessing invalid dip_ctx during destroying QP |
|  | CVE-2024-54031 | `542ed8145e6f` | mainline | netfilter: nft_set_hash: unaligned atomic read on struct nft_set_ext |
|  | CVE-2024-57930 | `afc6717628f9` | mainline | tracing: Have process_string() also allow arrays |
|  | CVE-2025-21671 | `212fe1c0df4a` | mainline | zram: fix potential UAF of zram table |
|  | CVE-2025-21817 | `7c0be4ead1f8` | mainline | block: mark GFP_NOIO around sysfs ->store() |
|  | CVE-2025-21679 | `fe4de594f7a2` | mainline | btrfs: add the missing error handling inside get_canonical_dev_path |
|  | CVE-2025-21794 | `0b43d98ff29b` | mainline | HID: hid-thrustmaster: fix stack-out-of-bounds read in usb_check_int_endpoints() |
|  | CVE-2025-21886 | `3d8c6f26893d` | mainline | RDMA/mlx5: Fix implicit ODP hang on parent deregistration |
|  | CVE-2025-21942 | `5a4041f2c472` | mainline | btrfs: zoned: fix extent range end unlock in cow_file_range() |
|  | CVE-2025-21923 | `e53fc232a65f` | mainline | HID: hid-steam: Fix use-after-free when detaching device |
|  | CVE-2025-22006 | `5f079290e591` | mainline | net: ethernet: ti: am65-cpsw: Fix NAPI registration sequence |
|  | CVE-2025-38099 | `14d17c78a4b1` | mainline | Bluetooth: Disable SCO support if READ_VOICE_SETTING is unsupported/broken |
|  | CVE-2025-37878 | `0ba3a4ab76fd` | mainline | perf/core: Fix WARN_ON(!ctx) in __free_event() for partial init |
|  | CVE-2025-37871 | `a1d14d931bf7` | mainline | nfsd: decrease sc_count directly if fail to queue dl_recall |
|  | CVE-2025-37929 | `fee4d171451c` | mainline | arm64: errata: Add missing sentinels to Spectre-BHB MIDR arrays |
|  | CVE-2025-37962 | `eb4447bcce91` | mainline | ksmbd: fix memory leak in parse_lease_state() |
|  | CVE-2025-38017 | `d9ec73301099` | mainline | fs/eventpoll: fix endless busy loop after timeout has expired |
|  | CVE-2025-37953 | `376947861013` | mainline | sch_htb: make htb_deactivate() idempotent |
|  | CVE-2025-37965 | `9984db637420` | mainline | drm/amd/display: Fix invalid context error in dml helper |
|  | CVE-2025-38092 | `10379171f346` | mainline | ksmbd: use list_first_entry_or_null for opinfo_get_list() |
|  | CVE-2025-38404 | `099cf1fbb8af` | mainline | usb: typec: displayport: Fix potential deadlock |
|  | CVE-2025-38379 | `3bbe46716092` | mainline | smb: client: fix warning when reconnecting channel |
|  | CVE-2025-38411 | `9df7b5ebead6` | mainline | netfs: Fix double put of request |
|  | CVE-2025-38656 | `cf80c02a9fdb` | mainline | wifi: iwlwifi: Fix error code in iwl_op_mode_dvm_start() |
|  | CVE-2025-38736 | `24ef2f53c07f` | mainline | net: usb: asix_devices: Fix PHY address mask in MDIO bus initialization |
|  | CVE-2025-39965 | `cd8ae32e4e46` | mainline | xfrm: xfrm_alloc_spi shouldn't use 0 as SPI |
|  | CVE-2025-39882 | `4de37a48b6b5` | mainline | drm/mediatek: fix potential OF node use-after-free |
|  | CVE-2025-40022 | `d0ca0df179c4` | mainline | crypto: af_alg - Fix incorrect boolean values in af_alg_ctx |
|  | CVE-2025-40090 | `88f170814fea` | mainline | ksmbd: fix recursive locking in RPC handle list access |
|  | CVE-2025-40348 | `6ed8bfd24ce1` | mainline | slab: Avoid race on slab->obj_exts in alloc_slab_obj_exts |
|  | CVE-2025-68252 | `fff111bf45cb` | mainline | misc: fastrpc: Fix dma_buf object leak in fastrpc_map_lookup |
|  | CVE-2025-68300 | `7b6dcd9bfd86` | mainline | fs/namespace: fix reference leak in grab_requested_mnt_ns |
|  | CVE-2025-68357 | `7fd8720dff2d` | mainline | iomap: allocate s_dio_done_wq for async reads as well |
|  | CVE-2025-68291 | `f07f4ea53e22` | mainline | mptcp: Initialise rcv_mss before calling tcp_send_active_reset() in mptcp_do_fastclose(). |
|  | CVE-2025-68299 | `d27c71257825` | mainline | afs: Fix delayed allocation of a cell's anonymous key |
|  | CVE-2025-71146 | `2e2a72076688` | mainline | netfilter: nf_conncount: fix leaked ct in error paths |
|  | CVE-2025-71145 | `b4b64fda4d30` | mainline | usb: phy: isp1301: fix non-OF device reference imbalance |
|  | CVE-2026-22983 | `7d11e047eda5` | mainline | net: do not write to msg_get_inq in callee |
|  | CVE-2026-22988 | `c92510f5e3f8` | mainline | arp: do not assume dev_hard_header() does not change skb->head |
|  | CVE-2026-22995 | `f0d385f6689f` | mainline | ublk: fix use-after-free in ublk_partition_scan_work |
|  | CVE-2026-23082 | `79a6d1bfe114` | mainline | can: gs_usb: gs_usb_receive_bulk_callback(): unanchor URL on usb_submit_urb() error |
|  | CVE-2026-45892 | `6d882ea3b093` | mainline | ext4: drop extent cache after doing PARTIAL_VALID1 zeroout |
|  | CVE-2026-23117 | `42fb5f3deb58` | mainline | ice: add missing ice_deinit_hw() in devlink reinit path |
|  | CVE-2026-23155 | `494fc029f662` | mainline | can: gs_usb: gs_usb_receive_bulk_callback(): fix error message |
|  | CVE-2026-23202 | `bf4528ab28e2` | mainline | spi: tegra210-quad: Protect curr_xfer in tegra_qspi_combined_seq_xfer |
|  | CVE-2026-23207 | `edf9088b6e1d` | mainline | spi: tegra210-quad: Protect curr_xfer check in IRQ handler |
|  | CVE-2026-43220 | `9e249c484128` | mainline | iommu/amd: serialize sequence allocation under concurrent TLB invalidations |
|  | CVE-2026-23200 | `bbf4a17ad9ff` | mainline | ipv6: Fix ECMP sibling count mismatch when clearing RTF_ADDRCONF |
|  | CVE-2026-23341 | `8363c0286333` | mainline | accel/amdxdna: Fix crash when destroying a suspended hardware context |
|  | CVE-2026-23288 | `1110a949675e` | mainline | accel/amdxdna: Fix out-of-bounds memset in command slot handling |
|  | CVE-2026-23355 | `aac9b27f7c1f` | mainline | ata: libata: cancel pending work after clearing deferred_qc |
|  | CVE-2026-23309 | `457965c13f08` | mainline | tracing: Add NULL pointer check to trigger_data_free() |
|  | CVE-2026-43369 | `062ea905fff7` | mainline | drm/amd: Fix NULL pointer dereference in device cleanup |
|  | CVE-2026-43367 | `72ecb1dae727` | mainline | drm/amd: Fix a few more NULL pointer dereference in device cleanup |
|  | CVE-2026-31437 | `e9075e420a1e` | mainline | netfs: Fix NULL pointer dereference in netfs_unbuffered_write() on retry |
|  | CVE-2026-43070 | `a3125bc01884` | mainline | bpf: Reset register ID for BPF_END value tracking |
|  | CVE-2026-43371 | `881a0263d502` | mainline | net: macb: Shuffle the tx ring before enabling tx |
|  | CVE-2026-43440 | `87c2302813ab` | mainline | net/mana: Null service_wq on setup error to prevent double destroy |
|  | CVE-2026-23451 | `b7405dcf7385` | mainline | bonding: prevent potential infinite loop in bond_header_parse() |
|  | CVE-2026-23443 | `bf504b229cb8` | mainline | ACPI: processor: Fix previous acpi_processor_errata_piix4() fix |
|  | CVE-2026-31573 | `e8d97c270cb4` | mainline | media: verisilicon: Fix kernel panic due to __initconst misuse |
|  | CVE-2026-31727 | `e002e92e88e1` | mainline | usb: gadget: u_ether: Fix NULL pointer deref in eth_get_drvinfo |
|  | CVE-2026-31513 | `9d87cb22195b` | mainline | Bluetooth: L2CAP: Fix stack-out-of-bounds read in l2cap_ecred_conn_req |
|  | CVE-2026-31413 | `c845894ebd6f` | mainline | bpf: Fix unsound scalar forking in maybe_fork_scalars() for BPF_OR |
|  | CVE-2026-31444 | `48623ec358c1` | mainline | ksmbd: fix use-after-free and NULL deref in smb_grant_oplock() |
|  | CVE-2026-43067 | `bb81702370fa` | mainline | ext4: handle wraparound when searching for blocks for indirect mapped blocks |
|  | CVE-2026-31742 | `40014493cece` | mainline | vt: discard stale unicode buffer on alt screen exit after resize |
|  | CVE-2026-43323 | `1319ea57529e` | mainline | sched/fair: Fix zero_vruntime tracking fix |
|  | CVE-2026-43084 | `936206e3f6ff` | mainline | netfilter: nfnetlink_queue: make hash table per queue |
|  | CVE-2026-46048 | `7a5f1cd22d47` | mainline | ALSA: caiaq: fix usb_dev refcount leak on probe failure |
|  | CVE-2026-64092 | `77098e4bea37` | mainline | batman-adv: tp_meter: fix tp_vars reference leak in receiver shutdown |
|  | CVE-2026-64139 | `af92ee994cc7` | mainline | ksmbd: fix SID memory leak in set_posix_acl_entries_dacl() on overflow |
|  | CVE-2026-52966 | `dc366607c41c` | mainline | drm: Replace old pointer to new idr |
|  | CVE-2026-64028 | `576ec047d20b` | mainline | tracing: Avoid NULL return from hist_field_name() on truncation |
|  | CVE-2026-64016 | `3515503322f4` | mainline | ksmbd: fix durable reconnect error path file lifetime |
|  | CVE-2026-63909 | `0e60dafe97ec` | mainline | ksmbd: OOB read regression in smb_check_perm_dacl() ACE-walk loops |
|  | CVE-2026-63885 | `7164d78559b0` | mainline | drm/gem: fix race between change_handle and handle_delete |
|  | CVE-2026-64240 | `171022c7d594` | mainline | media: rc: igorplugusb: fix control request setup packet |
|  | CVE-2026-53265 | `d3f0a606b9f2` | mainline | dm cache policy smq: check allocation under invalidate lock |
|  | CVE-2026-53243 | `6d99479799c6` | mainline | rseq: Fix using an uninitialized stack variable in rseq_exit_user_update() |
|  | CVE-2026-53163 | `40a25d59e85b` | mainline | locking/rtmutex: Skip remove_waiter() when waiter is not enqueued |
|  | CVE-2026-53145 | `1a4f03d22fb6` | mainline | drm/gem: Try to fix change_handle ioctl, attempt 4 |
|  | CVE-2026-64257 | `8986c932905e` | mainline | smb: client: reject overlapping data areas in SMB2 responses |
|  | CVE-2026-98870 | `b10665730fbf` | mainline | ksmbd: remove stale channels from all sessions on teardown |
|  | CVE-2026-68427 | `266cddf7bd0f` | mainline | gpu: host1x: Fix use-after-free in host1x_bo_clear_cached_mappings |
|  | CVE-2026-68344 | `71132cedd1ec` | mainline | usb: atm: ueagle-atm: reject descriptors that confuse probe and disconnect |
|  | CVE-2026-68434 | `7fb13fd7e9a5` | mainline | serial: 8250_mid: Fix NULL function pointer dereference on DNV/ICX-D/SNR platforms |
|  | CVE-2026-80889 | `050f010f920d` | mainline | can: isotp: fix timer drain order, wakeup handling and tx_gen ordering |
|  | CVE-2026-74639 | `2615f0fb90df` | mainline | ALSA: us144mkii: re-anchor capture URBs on resubmission |
|  | CVE-2026-80728 | `b96c529cd255` | mainline | Revert "drm/amdgpu: fix aperture mapping leak" |
|  | CVE-2026-74753 | `fa091f46c383` | mainline | perf: Reject exited events as group leaders |
|  | CVE-2026-74642 | `f8a80cfb6861` | mainline | ALSA: usb: Fix UAF at delayed release of MIDI2 EPs |
|  | CVE-2026-98353 | `00baeade709f` | mainline | RDMA/erdma: Use IRQ-safe XArray helpers for QP and CQ tables |
|  | CVE-2026-98316 | `221253723dc5` | mainline | ALSA: bcd2000: Fix race between rawmidi and disconnect |
|  | CVE-2026-98939 | `e3ee38c1bc0b` | mainline | x86/mm: Drop unnecessary PMD page copy when freeing |
|  | CVE-2026-98719 | `8abbc76120a7` | mainline | KVM: SEV: Nullify "have run CPUs" mask pointer when freeing it |
|  | CVE-2026-98718 | `973ea70393e8` | mainline | KVM: SEV: Do cache maintenance on the source VM *before* clearing SEV state |
|  | CVE-2026-99009 | `ac022970e9fb` | mainline | Bluetooth: RFCOMM: connect the session socket without rfcomm_mutex |
|  | CVE-2026-99093 | `2fb552b0bee7` | mainline | mm: don't schedule deferred kernel page table freeing while booting |
|  | CVE-2026-99151 | `55a67aa89342` | mainline | drm/amd/display: Fix NULL sink dereference in USB4 bandwidth functions |

Fix any of these with `fasttrack cve <ID>` (add `--claude` for a Claude-made backport).
